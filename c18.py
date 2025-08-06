from Utils.AES import AES_CTR
from base64 import b64decode

if __name__ == "__main__":
    s = b64decode(b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==') 
    key = b'YELLOW SUBMARINE'
    nonce = 0

    print(AES_CTR(key, nonce).dec(s).decode('utf-8'))