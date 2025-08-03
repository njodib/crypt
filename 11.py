from utils import pkcs7_pad
from random import randint, randbytes
import numpy as np
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Utils.AES import aes_cbc_encrypt, aes_ecb_encrypt

def rand_aes_encrypt(plaintext, key):
    plaintext = randbytes(randint(5,10)) + plaintext + randbytes(randint(5,10))
    plaintext = pkcs7_pad(plaintext, 16)
    if randint(0,1) == 0:
        return aes_cbc_encrypt(plaintext, key, randbytes(16)), "CBC"
    else:
        return aes_ecb_encrypt(plaintext, key), "ECB"

def aes_detect_mode(ciphertext):
    array = np.frombuffer(ciphertext, dtype="uint8").reshape(-1, 16)
    duplicate_blocks = len(array) - len(np.unique(array, axis=0))
    return "ECB" if 0<duplicate_blocks else "CBC"

for _ in range(12):
    plaintext = b"testtubebabybarf"*4
    ciphertext, mode = rand_aes_encrypt(plaintext, randbytes(16))
    detected_mode = aes_detect_mode(ciphertext)
    assert mode == detected_mode
print("11: Success")





