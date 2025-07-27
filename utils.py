import binascii
from base64 import b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def fixed_xor(a: bytes, b: bytes) -> bytes:
    return bytes (i^j for i,j in zip(a,b))

def single_xor(a: bytes, key: int) -> bytes:
    return bytes (i^key for i in a)

def repeating_xor(a: bytes, key) -> bytes:
    res = []
    for i in range(len(a)):
        res.append(a[i] ^ key[i%len(key)])
    sol = binascii.hexlify(bytes(res))
    return sol

frequencies = {'a': 0.0855, 'b': 0.0160, 'c': 0.0316, 'd': 0.0387, 'e': 0.1209,
               'f': 0.0218, 'g': 0.0209, 'h': 0.0496, 'i': 0.0732, 'j': 0.0022,
               'k': 0.0081, 'l': 0.0420, 'm': 0.0253, 'n': 0.0717, 'o': 0.0747,
               'p': 0.0206, 'q': 0.0010, 'r': 0.0633, 's': 0.0673, 't': 0.0894,
               'u': 0.0268, 'v': 0.0106, 'w': 0.0182, 'x': 0.0019, 'y': 0.0172,
               'z': 0.0011}

def error(candidate: bytes) -> float:
    l = len(candidate)
    score = 0
    for char, expected_freq in frequencies.items():
        freq = candidate.count(ord(char)) / l
        err = abs(freq - expected_freq)
        score += err
    return score

def best_xor_key(hex: bytes) -> int:
    best_key = -1
    min_error = float('inf')
    for key in range(32,128):
        candidate = single_xor(hex, key)
        candidate_error = error(candidate)
        #print(key, candidate_error)
        if candidate_error < min_error:
            best_key = key
            min_error = candidate_error
    return best_key

def decrypt_aes_ecb(ciphertext, key):
    cipher =  Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    return cipher.decryptor().update(ciphertext)

def pkcs7_pad(text, block_size):
    if len(text) % block_size == 0:
        return text
    pad_size = block_size - (len(text) % block_size)
    return b"".join([text, bytes([pad_size]) * pad_size])