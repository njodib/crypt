from utils import decrypt_aes_ecb, pkcs7_pad, fixed_xor
from base64 import b64decode

def aes_cbc_decrypt(ciphertext, key, iv = [0]*16):
    decrypted = (fixed_xor(decrypt_aes_ecb(ciphertext[0:16], key), iv))
    for i in range(16, len(ciphertext), 16):
        decrypted += (fixed_xor(decrypt_aes_ecb(ciphertext[i:i+16], key), ciphertext[i-16:i]))
    return decrypted

with open("10.txt") as input_file:
    data = b64decode(input_file.read())
print(aes_cbc_decrypt(pkcs7_pad(data, 16), b"YELLOW SUBMARINE").decode('utf-8'))