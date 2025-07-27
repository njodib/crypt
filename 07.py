from base64 import b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from utils import decrypt_aes_ecb



key = b"YELLOW SUBMARINE"
with open("07.txt") as input_file:
    ciphertext = b64decode(input_file.read())
print(decrypt_aes_ecb(ciphertext, key).decode('utf-8'))