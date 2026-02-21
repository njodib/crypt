from base64 import b64decode
import requests
from Utils.AES import AES_ECB

if __name__ == "__main__":
    # Get ciphertext
    URL = "https://www.cryptopals.com/static/challenge-data/7.txt"
    ctxt = b64decode(requests.get(URL).text)

    # Decrypt into plaintext with given key
    ptxt = AES_ECB(b'YELLOW SUBMARINE').decrypt(ctxt)
    print(ptxt.decode().rstrip())