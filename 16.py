from Utils.AES import aes_cbc_encrypt, aes_cbc_decrypt, aes_ecb_decrypt, aes_ecb_encrypt
from random import randbytes
from Utils.Padding import pkcs7
from Utils.BytesLogic import xor

class Oracle:
    def __init__(self):
        self.iv = randbytes(16)
        self.key = randbytes(16)
        self.pre = b"comment1=cooking%20MCs;userdata="
        self.post = b";comment2=%20like%20a%20pound%20of%20bacon"

    def encrypt(self, user_input: bytes):
        ptxt = user_input.replace(';', '').replace('=', '').encode()
        ptxt = self.pre + ptxt + self.post
        ctxt = aes_cbc_encrypt(pkcs7(ptxt, 16), self.key, self.iv)
        #print(ctxt[32:48])
        return ctxt

    def decrypt_and_check_admin(self, ctxt):
        data = aes_cbc_decrypt(ctxt, self.key, self.iv)
        return b';admin=true' in data

profile = Oracle()
ctxt = profile.encrypt("hello9admin9true")
block2 = ctxt[16:32]
bit_flipper = b'\x00'*5+b'\x02'+b'\x00'*5+b'\x04'+b'\x00'*4
flipped_block2 = xor(block2, bit_flipper)
ctxt_flipped = ctxt[:16] + flipped_block2 + ctxt[32:]

assert profile.decrypt_and_check_admin(ctxt_flipped)
print("SUCCESS")