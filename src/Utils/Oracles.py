from random import randint, randbytes, getrandbits
import random
from Utils.AES import AES_ECB, AES_CBC, AES_CTR
from Utils.Padding import PKCS7
from base64 import b64decode
from Crypto import Random
from Utils.CookieParser import kv_encode
import requests

class C11_Oracle:
    def __init__(self):
        self.padding = PKCS7(blocksize=16)
        if getrandbits(1):
            self.mode = "ECB"
            self.cipher = AES_ECB(randbytes(16))
        else:
            self.mode = "CBC"
            iv = randbytes(16)
            self.cipher = AES_CBC(randbytes(16), randbytes(16))

    def __call__(self, ptxt: bytes) -> bytes:
        # Prepend and append random bytes
        ptxt = randbytes(randint(5,10)) + ptxt + randbytes(randint(5,10))
        # Encrypt randomly using ECB or CBC
        return self.cipher.encrypt(ptxt)
    
    # For testing only. Oracle should never actually reveal its mode.
    def get_mode(self):
        return self.mode
    
# CHALLENGE 12
# Copy your oracle function to a new function that
# encrypts buffers under ECB mode using a consistent but
# unknown key (for instance, assign a single random key, once,
# to a global variable).  
class C12_Oracle:
    def __init__(self):
        self.cipher = AES_ECB(randbytes(16))
        self.unknown = b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
            "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
            "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
            "YnkK"
        )
        self.padding = PKCS7(16)

    def __call__(self, ptxt: bytes) -> bytes:
        return self.cipher.encrypt(ptxt + self.unknown)
    
'''
CHALLENGE 13
'''
class C13_Oracle:
    def __init__(self):
        self.cipher = AES_ECB(Random.new().read(16))

    def encrypt(self, email):
        email = email.replace('&', '').replace('=', '')
        d = {
            'email': email,
            'uid': 10,
            'role': 'user'
        }
        return self.cipher.encrypt(kv_encode(d).encode())

    def decrypt(self, ctxt):
        return self.cipher.decrypt(ctxt)

'''
CHALLENGE 14
'''
class C14_Oracle(C12_Oracle):
    def __init__(self):
        super(C14_Oracle, self).__init__()
        self.random_prefix = Random.new().read(randint(0, 255))

    def __call__(self, data):
        return self.cipher.encrypt(self.random_prefix + data + self.unknown)
    
'''
CHALLENGE 17
'''
class C17_Oracle:
    def __init__(self):
        self.iv = Random.new().read(16)
        self._key = Random.new().read(16)
        self._secrets = [
            b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
            b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
            b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
            b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
            b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
            b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
            b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
            b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
            b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
            b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
        ]
        self.cipher = AES_CBC(self._key, self.iv)

    def get_encrypted_message(self):
        return self.cipher.encrypt(b64decode(random.choice(self._secrets)))

    def valid_ctxt(self, valid_ctxt):
        ptxt = self.cipher.decrypt(valid_ctxt, False)
        return PKCS7().detect_padding(ptxt)

'''
CHALLENGE 25
'''
class C25_Oracle:
    def __init__(self):
        self.key = randbytes(16)
        self.cipher = AES_CTR(self.key)
        URL = "https://www.cryptopals.com/static/challenge-data/25.txt"
        ptxt = AES_ECB(b"YELLOW SUBMARINE").decrypt(b64decode(requests.get(URL).text))
        self.ctxt = self.cipher.encrypt(ptxt)

    def edit(self, offset: int, newtext: bytes):  
        gg = bytes([a^b for a,b in zip(self.cipher.keystream(), newtext)])
        return self.ctxt[:offset] + gg + self.ctxt[offset+len(gg):]  

'''
CHALLENGE 26
'''
class C26_Oracle:
    def __init__(self):
        self.key = randbytes(16)
        self.ctr_obj = AES_CTR(self.key)

    def encode(self, plaintext: bytes) -> bytes:
        prefix = b"comment1=cooking%20MCs;userdata="
        suffix = b";comment2=%20like%20a%20pound%20of%20bacon"
        plaintext = plaintext.replace(b";", b"").replace(b"=", b"")
        ciphertext = self.ctr_obj.encrypt(prefix + plaintext + suffix)
        return ciphertext

    def parse(self, ciphertext: bytes) -> bool:
        decrypted = self.ctr_obj.decrypt(ciphertext)
        return b';admin=true;' in decrypted