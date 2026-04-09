from requests import post
from random import randint
from hashlib import sha256 as SHA2
from Utils.Hash import HMAC
import base64

def modexp(b, e, m):
    # https://en.wikipedia.org/wiki/Modular_exponentiation)
    # right --> left binary
    res = 1
    b = b % m
    while e > 0:
        if e % 2 == 1:
            res = (res * b) % m
        e = e // 2
        b = (b * b) % m
    return res

URL = "http://localhost:5000/"


response = post(URL, json={'test': 'Hello'}).json()
print(response)

N = 37
g = 2
k = 3
I = "goop@goop.com"
P = "hunter2"

a = randint(1, N - 1)
A = modexp(g, a, N)

response = post(URL, json={'I': I, 'A': A}).json()
salt = response.get('salt')
B = response.get('B')

uH = SHA2(str(A).encode() + str(B).encode()).digest()
u = int.from_bytes(uH, 'big')
xH = SHA2(int(salt).to_bytes(4, 'big') + P.encode()).digest()
x = int.from_bytes(xH, 'big')

base = (B - k * modexp(g, x, N)) % N
S = modexp(base, a + u * x, N)
K = SHA2(S.to_bytes((S.bit_length() + 7) // 8, 'big')).digest()

# SEND HMAC-SHA256(K, salt)
hm = HMAC.sha256(K, salt.to_bytes(4, 'big'))
response = post(URL, json={'hm': base64.b64encode(hm).decode('utf-8')}).json()