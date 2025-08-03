from utils import pkcs7_pad
from random import randint, randbytes
import numpy as np
from base64 import b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def aes_ecb_encrypt(plaintext, key):
    plaintext = pkcs7_pad(plaintext, 16)
    cipher =  Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    return cipher.encryptor().update(plaintext)

def get_block_size(ciphertext, key):
    len1 = len(aes_ecb_encrypt(ciphertext, key))
    bs = 1
    len2 = len(aes_ecb_encrypt(b"A"*bs + ciphertext, key))
    while len1 == len2:
        bs += 1
        len2 = len(aes_ecb_encrypt(b"A"*bs+ciphertext, key))
    return len2-len1

ciphertext = b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
YnkK")
key = randbytes(16)

block_size = get_block_size(ciphertext, key)
decrypted = b""

while ciphertext:
    short = aes_ecb_encrypt(b"A"*(block_size-1) + ciphertext, key)[:block_size]
    for char in range(256):
        byte = bytes([char])
        long = aes_ecb_encrypt(b"A"*(block_size-1) + byte + ciphertext, key)[:block_size]
        if short == long:
            decrypted += byte
            break
    ciphertext = ciphertext[1:]

print(decrypted.decode('utf-8'))
