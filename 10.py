from utils import pkcs7_pad, aes_cbc_decrypt
from base64 import b64decode

with open("10.txt") as input_file:
    data = b64decode(input_file.read())
print(aes_cbc_decrypt(pkcs7_pad(data, 16), b"YELLOW SUBMARINE").decode('utf-8'))