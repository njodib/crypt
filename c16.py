from random import randbytes
from Utils.BytesLogic import xor
from Utils.AES import AES_CBC

class Oracle:
    def __init__(self):
        self.iv = randbytes(16)
        self.key = randbytes(16)
        self.pre = b"comment1=cooking%20MCs;userdata="
        self.post = b";comment2=%20like%20a%20pound%20of%20bacon"
        self.cipher = AES_CBC(self.key, self.iv)

    def encode(self, user_input: bytes):
        ptxt = user_input.replace(b';', b'').replace(b'=', b'')
        ptxt = self.pre + ptxt + self.post
        ctxt = self.cipher.enc(ptxt, pad=True)
        return ctxt

    def parse(self, ctxt):
        data = self.cipher.dec(ctxt, strip=True)
        return b';admin=true' in data

if __name__ == "__main__":
    # how come i need comments to explain everything?
    # like ummm just look at it!!
    profile = Oracle()
    ctxt = profile.encode(b"hello9admin9true")
    block2 = ctxt[16:32]
    bit_flipper = b'\x00'*5+b'\x02'+b'\x00'*5+b'\x04'+b'\x00'*4
    flipped_block2 = xor(block2, bit_flipper)
    ctxt_flipped = ctxt[:16] + flipped_block2 + ctxt[32:]

    assert profile.parse(ctxt_flipped)
    print("SUCCESS")