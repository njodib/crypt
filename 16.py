from Utils.AES import aes_cbc_encrypt, aes_cbc_decrypt
from random import randbytes
from Utils.Padding import pkcs7

class Oracle:
    def __init__(self):
        self.iv = randbytes(16)
        self.key = randbytes(16)
        self.pre = b"comment1=cooking%20MCs;userdata="
        self.post = b";comment2=%20like%20a%20pound%20of%20bacon"

    def encrypt(self, user_input: bytes):
        ptxt = user_input.replace(';', '').replace('=', '').encode()
        ptxt = self.pre + ptxt + self.post
        return aes_cbc_encrypt(pkcs7(ptxt, 16), self.key, self.iv)

    def decrypt_and_check_admin(self, ctxt):
        data = aes_cbc_decrypt(ctxt, self.key, self.iv)
        #print(data)
        return data, b';admin=true' in data


profile = Oracle()
ctxt = profile.encrypt("puta;=puta")
##print(ctxt)
print(profile.decrypt_and_check_admin(ctxt))

