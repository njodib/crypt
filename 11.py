from utils import pkcs7_pad, encrypt_aes_cbc, encrypt_aes_ecb
from random import randint, randbytes
import numpy as np

def rand_aes_encrypt(plaintext):
    plaintext = randbytes(randint(5,10)) + plaintext + randbytes(randint(5,10))
    plaintext = pkcs7_pad(plaintext, 16)

    if randint(0,1) == 0:
        return encrypt_aes_cbc(plaintext, randbytes(16), randbytes(16)), "CBC"
    else:
        return encrypt_aes_ecb(plaintext, randbytes(16)), "ECB"

def aes_detect_mode(ciphertext):
    array = np.frombuffer(ciphertext, dtype="uint8").reshape(-1, 16)
    duplicate_blocks = len(array) - len(np.unique(array, axis=0))
    return "ECB" if 0<duplicate_blocks else "CBC"


for _ in range(12):
    plaintext = b"testtubebabybarf"*4
    ciphertext, mode = rand_aes_encrypt(plaintext)
    detected_mode = aes_detect_mode(ciphertext)
    assert mode == detected_mode
print("11: Success")





