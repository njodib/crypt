from Crypto.Cipher import AES
from struct import pack
from base64 import b64decode

s = b64decode(b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==') 
key = b'YELLOW SUBMARINE'
nonce = 0

def dec():
    def ks():
        ct = 0
        cipher = AES.new(key, AES.MODE_ECB)
        while True:
            pee = pack("QQ", nonce, ct) #packs as little-endian 64-bit
            ct += 1
            yield from cipher.encrypt(pee)
    return bytes((xb^yb) for xb,yb in zip(bytearray(s), ks()))

print(dec().decode())