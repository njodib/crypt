from base64 import b64decode
from random import randbytes
from Crypto.Cipher import AES
from Utils.AES import AES_CTR

class Oracle:
    def __init__(self):
        self.key = randbytes(16)
        self.ctr = AES_CTR(self.key)
        with open("Data/07.txt") as input_file:
            self.ctxt = self.ctr.enc(AES.new(b"YELLOW SUBMARINE", AES.MODE_ECB).decrypt(b64decode(input_file.read())))

    def edit(self, offset: int, new_text: bytes):  
        gg = bytes([a^b for a,b in zip(self.ctr.ks(), new_text)])
        return self.ctxt[:offset] + gg + self.ctxt[offset+len(gg):]  

o = Oracle()
ctxt = o.edit(0,'') #zero change
print(o.edit(0, ctxt).decode()) #xors ctxt with keystream for ptxt