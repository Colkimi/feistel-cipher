#!/usr/bin/env python3

from Crypto.Util.number import *
from gmpy2 import *
import hashlib

d = 175
ROUNDS = 5

get_context().precision = 2048

def pad(m, d):
    if len(str(m)) < d:
        m = str(m) + '1' * (d - len(str(m)))
    return int(m)

def genkey(d):
    p = getPrime(d * 4)
    q = getPrime(d * 4)
    n = p * q
    
    skey = getRandomRange(10 ** (d - 1), 10 ** d)
    
    pkey1 = int(10**d * (sqrt(skey) - floor(sqrt(skey))))
    pkey2 = int(10**d * (cbrt(skey) - floor(cbrt(skey))))
    pkey3 = int(10**d * (sqrt(skey * 2) - floor(sqrt(skey * 2))))
    
    h = int(hashlib.sha512(str(skey).encode()).hexdigest(), 16)
    pkey4 = h % (10 ** d)
    
    return (pkey1, pkey2, pkey3, pkey4, n), (skey, p, q)

def feistel_round(left, right, round_key, modulus):
    """Non-linear Feistel function"""
    temp = (right + round_key) % modulus
    f_output = pow(temp, 3, modulus)
    new_left = right
    new_right = (left + f_output) % modulus
    return new_left, new_right

def derive_round_keys(pkeys, rounds, m_len):
    """Derive round keys from public keys"""
    round_keys = []
    pkey1, pkey2, pkey3, pkey4, n = pkeys
    
    for i in range(rounds):
        h = hashlib.sha512(f"{pkey1}{pkey2}{pkey3}{pkey4}{i}{m_len}".encode()).digest()
        rk = int.from_bytes(h, 'big') % n
        round_keys.append(rk)
    
    return round_keys

def encrypt(m, pkeys):
    pkey1, pkey2, pkey3, pkey4, n = pkeys
    d = len(str(pkey1))
    
    m = pad(m, d)
    
    m = (m * pkey1 + pkey2) % n
    m = pow(m, pkey3 % 65537 | 1, n)  
    
    bit_len = m.bit_length()
    half = bit_len // 2
    mask = (1 << half) - 1
    left = m >> half
    right = m & mask
    
    round_keys = derive_round_keys(pkeys, ROUNDS, d)
    
    for i in range(ROUNDS):
        left, right = feistel_round(left, right, round_keys[i], n)
    
    c = (left << half) | right
    
    c = (c * pkey4 + pkey3 * pkey2) % n
    c = (c + pkey1 * pkey4) % n
    
    c = pow(c, (pkey2 % 256) | 1, n)  
    
    return c

if __name__ == "__main__":

    pass
