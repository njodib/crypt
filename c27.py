from random import randbytes
from Utils.AES import AES_CBC
from Utils.BytesLogic import xor_bytes

BS = 16 #BLOCKSIZE

class Oracle:
    def __init__(self):
        self.key = randbytes(BS)
        self.nonce = self.key
        self.cipher = AES_CBC(self.key, self.nonce)

    def encode(self, plaintext: bytes) -> bytes:
        prefix = b"comment1=cooking%20MCs;userdata="
        suffix = b";comment2=%20like%20a%20pound%20of%20bacon"
        ptxt = prefix + plaintext.replace(b";", b"").replace(b"=", b"") + suffix
        return self.cipher.enc(ptxt)

    def parse(self, ciphertext: bytes) -> bool:
        decrypted = self.cipher.dec(ciphertext)
        try: decoded = decrypted.decode('ascii')
        except UnicodeDecodeError: raise ValueError('Illegal characters', decrypted)
        return ';admin=true;' in decoded

if __name__ == '__main__':
    # Setup ctxt with >3 blocks
    oracle = Oracle()
    ctxt = bytearray(oracle.encode(b'A'*(3*BS)))
    
    # Parse (C1,0,C1,...)
    ctxt[BS:2*BS] = bytes([0]*BS) 
    ctxt[2*BS:3*BS] = ctxt[:BS]
    try: oracle.parse(ctxt) 
    except ValueError as e: decrypted = e.args[1] #expect error from 0s block
    key = xor_bytes(decrypted[:BS], decrypted[2*BS:3*BS]) #P1 xor P3
    
    # With the key, we read a decrypted ciphertext
    ciphertext = oracle.encode(b'____SUCCESSFUL DECRYPTION____')
    print(AES_CBC(key, key).dec(ciphertext))