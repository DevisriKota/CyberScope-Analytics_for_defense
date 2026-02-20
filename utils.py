import random

def generate_captcha():
    a = random.randint(1, 9)
    b = random.randint(1, 9)
    return a, b, a + b
