import random
from math import gcd
import hashlib


def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True


def generate_prime(start=100, end=300):
    p = random.randint(start, end)
    while not is_prime(p):
        p = random.randint(start, end)
    return p


def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1


def generate_keys():
    p = generate_prime()
    q = generate_prime()
    while q == p:
        q = generate_prime()
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    while gcd(e, phi) != 1:
        e += 2
    d = modinv(e, phi)
    return ((e, n), (d, n))  # (public, private)


def encrypt(message: str, pub_key):
    e, n = pub_key
    return [pow(ord(c), e, n) for c in message]


def decrypt(ciphertext, priv_key):
    d, n = priv_key
    return ''.join([chr(pow(c, d, n)) for c in ciphertext])


def sha256_digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()
