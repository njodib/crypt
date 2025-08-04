from Utils.Padding import pkcs7
from Utils.AES import aes_cbc_decrypt
from base64 import b64decode

with open("Data/10.txt") as input_file:
    ctxt = pkcs7(b64decode(input_file.read()), 16)
key = b"YELLOW SUBMARINE"
iv = [0]*16
print(aes_cbc_decrypt(ctxt, key, iv).decode('utf-8'))