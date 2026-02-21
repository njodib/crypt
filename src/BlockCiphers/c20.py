from random import randbytes, randint
from base64 import b64decode
from Utils.AES import AES_CTR
from Utils.BytesLogic import best_single_xor_key, xor_fixed
import requests

def decrypt_aes_ctr_fixed_nonce(ctxts):
    keystream = b"".join(
        best_single_xor_key(b"".join(bytes([c[i]]) for c in ctxts if i < len(c))) for i in range(max(map(len, ctxts)))
    )
    return [xor_fixed(c, keystream) for c in ctxts]

if __name__ == '__main__':
    KEY = randbytes(16)
    NONCE = randint(0,12345)
    URL = "https://www.cryptopals.com/static/challenge-data/20.txt"
    ctxts = [AES_CTR(KEY, NONCE).encrypt(b64decode(l)) for l in requests.get(URL).text.splitlines()]
    for ptxt in decrypt_aes_ctr_fixed_nonce(ctxts):
        print(ptxt.decode())