from random import randint, randbytes
from Utils.Padding import pkcs7
from Utils.AES import aes_cbc_encrypt, aes_cbc_decrypt, aes_ecb_decrypt
from base64 import b64decode

class Oracle:
    messages = list(map(b64decode, [
        'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
        'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
        'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
        'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
        'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
        'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
        'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
        'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
        'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
        'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
    ]))

    def __init__(self):
        self.key = randbytes(16)

    def enc(self):
        txt = pkcs7(self.messages[0], 16)
        iv = randbytes(16)
        ctxt = aes_cbc_encrypt(txt, self.key, iv)
        return ctxt, iv

    def dec(self, ctxt, iv):
        aes_cbc_decrypt(ctxt, self.key, iv)
        #Function does not return. Instead check for exceptions on padding failures.

puta = Oracle()
ctxt, iv = puta.enc()
print(ctxt, iv)
puta.dec(ctxt, iv)