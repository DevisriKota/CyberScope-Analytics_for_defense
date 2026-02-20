# app.py  (FULL FINAL VERSION - one-DB-connection-per-request, no "database locked")

from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
from passlib.hash import pbkdf2_sha256
from datetime import datetime, timedelta
from utils import generate_captcha

app = Flask(__name__)
import os
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_change_me")
DB_NAME = "database.db"

# ---------------- DB (WAL + timeout) ----------------

def get_db():
    conn = sqlite3.connect(DB_NAME, timeout=10, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    return conn

def init_db():
    with get_db() as conn:
        c = conn.cursor()

        c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            failed_attempts INTEGER DEFAULT 0,
            locked_until TEXT,
            last_ip TEXT,
            last_attempt_ts TEXT
        )
        """)

        c.execute("""
        CREATE TABLE IF NOT EXISTS user_profile (
            username TEXT PRIMARY KEY,
            ema_login_hour REAL DEFAULT 12.0,
            ema_attempt_gap REAL DEFAULT 30.0,
            known_ip TEXT
        )
        """)

        c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            ip TEXT,
            user_agent TEXT,
            status TEXT,
            action TEXT,
            attack_type TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            decision_reason TEXT,
            timestamp TEXT
        )
        """)

        c.execute("""
        CREATE TABLE IF NOT EXISTS ip_blocks (
            ip TEXT PRIMARY KEY,
            blocked_until TEXT,
            reason TEXT
        )
        """)

        c.execute("CREATE INDEX IF NOT EXISTS idx_logs_ip_status_time ON logs(ip, status, timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_logs_ip_time ON logs(ip, timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_logs_username_time ON logs(username, timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_logs_status_action_time ON logs(status, action, timestamp)")

def create_default_user():
    with get_db() as conn:
        c = conn.cursor()
        hashed = pbkdf2_sha256.hash("password123")
        c.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?,?)", ("admin", hashed))
        c.execute("INSERT OR IGNORE INTO user_profile (username, known_ip) VALUES (?,?)", ("admin", "127.0.0.1"))

init_db()
create_default_user()

# ---------------- CAPTCHA ----------------

def new_captcha():
    a, b, ans = generate_captcha()
    session["captcha_answer"] = ans
    session["captcha_a"] = a
    session["captcha_b"] = b

def captcha_question():
    if "captcha_a" not in session or "captcha_b" not in session:
        new_captcha()
    return f"{session['captcha_a']} + {session['captcha_b']}"

# ---------------- RISK HELPERS ----------------

def risk_level(score: int) -> str:
    if score <= 30: return "Low"
    if score <= 60: return "Medium"
    if score <= 80: return "High"
    return "Critical"

def classify_attack(captcha_failed, stuffing, rapid, failed_attempts):
    if stuffing: return "Credential Stuffing Campaign"
    if captcha_failed: return "Bot Attack"
    if rapid and failed_attempts >= 3: return "Brute Force (Rapid)"
    if failed_attempts >= 3: return "Brute Force"
    return "Normal"

# ---------------- IP BLOCK (uses one conn per call, quick) ----------------

def is_ip_blocked(c, ip: str, now: datetime):
    c.execute("SELECT blocked_until FROM ip_blocks WHERE ip=?", (ip,))
    row = c.fetchone()
    if not row:
        return False, 0

    until = datetime.fromisoformat(row[0])
    if now < until:
        return True, int((until - now).total_seconds())

    # expired -> cleanup
    c.execute("DELETE FROM ip_blocks WHERE ip=?", (ip,))
    return False, 0

def block_ip(c, ip: str, now: datetime, minutes: int, reason: str):
    until = now + timedelta(minutes=minutes)
    c.execute("INSERT OR REPLACE INTO ip_blocks (ip, blocked_until, reason) VALUES (?,?,?)",
              (ip, until.isoformat(), reason))

# ---------------- INDUSTRY FEATURES (cursor versions) ----------------

def credential_stuffing_detect(c, ip: str, now: datetime) -> bool:
    # one IP failing many usernames in last 2 mins
    window_start = (now - timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""
        SELECT COUNT(DISTINCT username)
        FROM logs
        WHERE ip=? AND status='FAIL' AND timestamp >= ?
    """, (ip, window_start))
    count_users = c.fetchone()[0]
    return count_users >= 5

def baseline_risk(c, username: str, ip: str, now: datetime, attempt_gap: float):
    reasons = []
    risk = 0

    c.execute("SELECT ema_login_hour, ema_attempt_gap, known_ip FROM user_profile WHERE username=?", (username,))
    row = c.fetchone()
    if not row:
        return 0, reasons

    ema_hour, ema_gap, known_ip = row
    if ema_hour is None: ema_hour = 12.0
    if ema_gap is None: ema_gap = 30.0
    if known_ip is None: known_ip = ""

    hour_now = now.hour + now.minute / 60.0

    if abs(hour_now - float(ema_hour)) >= 6:
        risk += 20
        reasons.append("Unusual login time (baseline deviation)")

    if known_ip and ip != known_ip:
        risk += 25
        reasons.append("Login from new IP (baseline deviation)")

    if attempt_gap < max(5, float(ema_gap) * 0.4):
        risk += 15
        reasons.append("Abnormally fast attempts (baseline deviation)")

    return risk, reasons

def update_user_baseline_with_cursor(c, username: str, ip: str, now: datetime, attempt_gap: float):
    hour = now.hour + now.minute / 60.0
    alpha = 0.2

    c.execute("SELECT ema_login_hour, ema_attempt_gap, known_ip FROM user_profile WHERE username=?", (username,))
    row = c.fetchone()

    if not row:
        c.execute("""
            INSERT INTO user_profile (username, ema_login_hour, ema_attempt_gap, known_ip)
            VALUES (?,?,?,?)
        """, (username, hour, attempt_gap, ip))
        return

    ema_hour, ema_gap, known_ip = row
    if ema_hour is None: ema_hour = 12.0
    if ema_gap is None: ema_gap = 30.0
    if known_ip is None: known_ip = ""

    ema_hour_new = alpha * hour + (1 - alpha) * float(ema_hour)
    ema_gap_new = alpha * attempt_gap + (1 - alpha) * float(ema_gap)

    if known_ip == "":
        known_ip = ip

    c.execute("""
        UPDATE user_profile
        SET ema_login_hour=?, ema_attempt_gap=?, known_ip=?
        WHERE username=?
    """, (ema_hour_new, ema_gap_new, known_ip, username))

# ---------------- ROUTES ----------------

@app.route("/", methods=["GET", "POST"])
def login():
    ip = (request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
      or request.remote_addr
      or "unknown")
    ua = request.headers.get("User-Agent", "unknown")
    now = datetime.now()

    if request.method == "GET":
        return render_template("login.html", ip=ip, error="", failed=0, captcha=False, captcha_question="", lock_time=0)

    # POST
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    captcha_input = request.form.get("captcha_answer", "").strip()

    with get_db() as conn:
        c = conn.cursor()

        # IP block check (same connection)
        blocked, remaining = is_ip_blocked(c, ip, now)
        if blocked:
            return render_template("login.html", ip=ip,
                                   error=f"IP blocked. Try again in {remaining}s.",
                                   failed=0, captcha=False, captcha_question="", lock_time=remaining)

        # user fetch
        c.execute("""
            SELECT id, username, password, failed_attempts, locked_until, last_ip, last_attempt_ts
            FROM users WHERE username=?
        """, (username,))
        user = c.fetchone()

        if not user:
            return render_template("login.html", ip=ip, error="User not found",
                                   failed=0, captcha=False, captcha_question="", lock_time=0)

        user_id, uname, pw_hash, failed_attempts, locked_until, last_ip, last_ts = user

        # attempt gap / rapid detection
        attempt_gap = 30.0
        rapid = False
        if last_ts:
            try:
                prev = datetime.fromisoformat(last_ts)
                attempt_gap = (now - prev).total_seconds()
                if attempt_gap < 10:
                    rapid = True
            except:
                pass

        # lock check
        if locked_until:
            until_dt = datetime.fromisoformat(locked_until)
            if now < until_dt:
                remain = int((until_dt - now).total_seconds())
                new_captcha()
                return render_template("login.html", ip=ip,
                    error=f"Account locked. Try again in {remain}s.",
                    failed=min(failed_attempts, 5),
                    captcha=True,
                    captcha_question=captcha_question(),
                    lock_time=remain
                )
            else:
                c.execute("UPDATE users SET locked_until=NULL WHERE id=?", (user_id,))

        # industry detections
        stuffing = credential_stuffing_detect(c, ip, now)
        base_risk, base_reasons = baseline_risk(c, uname, ip, now, attempt_gap)

        risk = 0
        reasons = []

        if rapid:
            risk += 15
            reasons.append("Rapid attempts")

        risk += base_risk
        reasons += base_reasons

        if stuffing:
            risk += 45
            reasons.append("Multiple usernames from same IP (credential stuffing)")
            block_ip(c, ip, now, minutes=2, reason="Credential stuffing detected")

        captcha_required = (failed_attempts >= 3) or (risk >= 35) or stuffing
        captcha_failed = False

        # CAPTCHA validation
        if captcha_required:
            if "captcha_answer" not in session:
                new_captcha()

            try:
                provided = int(captcha_input)
            except:
                provided = -999

            if provided != session.get("captcha_answer"):
                captcha_failed = True
                risk += 25
                reasons.append("CAPTCHA failed")

                attack = classify_attack(True, stuffing, rapid, failed_attempts)
                lvl = risk_level(risk)

                c.execute("""
                    INSERT INTO logs (username, ip, user_agent, status, action, attack_type, risk_score, risk_level, decision_reason, timestamp)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                """, (uname, ip, ua, "FAIL", "CAPTCHA_FAILED", attack, risk, lvl,
                      " + ".join(reasons), now.strftime("%Y-%m-%d %H:%M:%S")))

                # update last attempt (same conn)
                c.execute("UPDATE users SET last_attempt_ts=?, last_ip=? WHERE id=?", (now.isoformat(), ip, user_id))

                new_captcha()
                return render_template("login.html", ip=ip,
                    error="Incorrect CAPTCHA",
                    failed=min(failed_attempts, 5),
                    captcha=True,
                    captcha_question=captcha_question(),
                    lock_time=0
                )

        # PASSWORD verify
        if pbkdf2_sha256.verify(password, pw_hash):
            c.execute("""
                UPDATE users SET failed_attempts=0, locked_until=NULL, last_ip=?, last_attempt_ts=?
                WHERE id=?
            """, (ip, now.isoformat(), user_id))

            # baseline update uses SAME cursor (no lock)
            update_user_baseline_with_cursor(c, uname, ip, now, attempt_gap)

            c.execute("""
                INSERT INTO logs (username, ip, user_agent, status, action, attack_type, risk_score, risk_level, decision_reason, timestamp)
                VALUES (?,?,?,?,?,?,?,?,?,?)
            """, (uname, ip, ua, "SUCCESS", "LOGIN", "Normal", 0, "Low",
                  "Login successful", now.strftime("%Y-%m-%d %H:%M:%S")))

            session["user"] = uname
            session["ip"] = ip
            return redirect(url_for("dashboard"))

        # WRONG password
        failed_attempts += 1
        failed_attempts = min(failed_attempts, 5)
        risk += 20
        reasons.append("Wrong password")

        action = "FAILED"
        if failed_attempts >= 5 or risk >= 70:
            lock_seconds = 60 if risk < 85 else 120
            until_dt = now + timedelta(seconds=lock_seconds)
            c.execute("UPDATE users SET locked_until=? WHERE id=?", (until_dt.isoformat(), user_id))
            action = "LOCKED"
            reasons.append(f"Account locked for {lock_seconds}s")

        attack = classify_attack(captcha_failed, stuffing, rapid, failed_attempts)
        lvl = risk_level(risk)

        c.execute("UPDATE users SET failed_attempts=?, last_attempt_ts=?, last_ip=? WHERE id=?",
                  (failed_attempts, now.isoformat(), ip, user_id))

        c.execute("""
            INSERT INTO logs (username, ip, user_agent, status, action, attack_type, risk_score, risk_level, decision_reason, timestamp)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (uname, ip, ua, "FAIL", action, attack, risk, lvl,
              " + ".join(reasons), now.strftime("%Y-%m-%d %H:%M:%S")))

        if failed_attempts >= 3:
            new_captcha()

        return render_template("login.html", ip=ip,
            error="Invalid credentials",
            failed=failed_attempts,
            captcha=(failed_attempts >= 3),
            captcha_question=captcha_question() if (failed_attempts >= 3) else "",
            lock_time=0
        )

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=session.get("user"), ip=session.get("ip"))

@app.route("/analytics")
def analytics():
    if "user" not in session:
        return redirect(url_for("login"))

    with get_db() as conn:
        c = conn.cursor()

        c.execute("SELECT COUNT(*) FROM logs")
        total = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM logs WHERE status='FAIL'")
        fails = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM logs WHERE action='LOCKED'")
        locked = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM logs WHERE risk_level IN ('High','Critical')")
        high = c.fetchone()[0]

        c.execute("""
            SELECT username, ip, status, action, attack_type, risk_level, risk_score, decision_reason, timestamp
            FROM logs ORDER BY id DESC LIMIT 30
        """)
        logs = c.fetchall()

        c.execute("""
            SELECT ip, COUNT(*) as cnt
            FROM logs WHERE status='FAIL'
            GROUP BY ip ORDER BY cnt DESC LIMIT 5
        """)
        top_ips = c.fetchall()

    return render_template("analytics.html",
        total=total, fails=fails, locked=locked, high=high,
        logs=logs, top_ips=top_ips
    )

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    # IMPORTANT: threaded=False prevents SQLite lock issues on Windows
    app.run(debug=False, threaded=False)
