from Utils.AES import AES_CTR
from base64 import b64decode

if __name__ == '__main__':
    ctxt = b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
    KEY = b'YELLOW SUBMARINE'
    NONCE = 0
    ptxt = AES_CTR(KEY, NONCE).decrypt(ctxt)
    print(ptxt.decode())