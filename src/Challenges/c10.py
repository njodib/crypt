from base64 import b64decode
import requests
from Utils.AES import AES_CBC

if __name__ == '__main__':
    # Save ciphertext
    URL = "https://www.cryptopals.com/static/challenge-data/10.txt"
    ctxt = b64decode(requests.get(URL).text)

    # Compute and print the decrypted plaintext with the given input
    cipher = AES_CBC(b'YELLOW SUBMARINE', b'\x00'*16)
    ptxt = cipher.decrypt(ctxt)
    print(ptxt.decode().rstrip())

    # Ensure that encryption/decryption are symmetric
    assert cipher.encrypt(ptxt) == ctxt