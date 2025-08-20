from random import randbytes
from Utils.BytesLogic import xor
from Utils.AES import AES_CTR

# globals
AES_BLOCK_SIZE = 16

class Oracle:
    def __init__(self):
        self.key = randbytes(AES_BLOCK_SIZE)
        self.ctr_obj = AES_CTR(self.key)

    def encode(self, plaintext: bytes) -> bytes:
        prefix = b"comment1=cooking%20MCs;userdata="
        suffix = b";comment2=%20like%20a%20pound%20of%20bacon"
        plaintext = plaintext.replace(b";", b"").replace(b"=", b"")
        ciphertext = self.ctr_obj.enc(prefix + plaintext + suffix)
        return ciphertext

    def parse(self, ciphertext: bytes) -> bool:
        decrypted = self.ctr_obj.dec(ciphertext)
        return b';admin=true;' in decrypted

def prefix_length(oracle: Oracle) -> int:
    c1 = oracle.encode(b'XXXX')
    c2 = oracle.encode(b'OOOO')
    for i in range(len(c1)):
        if c1[i] != c2[i]:
            return i

if __name__ == '__main__':
       # setup oracle
    oracle = Oracle()
    p = prefix_length(oracle)
    
    # target is illegal input
    target = b';admin=true;'
    t = len(target)

    # XOR legal input with illegal input for new ctxt
    legal = b'A'*t  #legal input with target length
    mask = xor(target, legal) #mask changes ctxt of input to ctxt for target
    ctxt = oracle.encode(legal)
    ctxt = ctxt[:p] + xor(ctxt[p:p+t], mask) + ctxt[p+t:]
    
    # Test
    assert oracle.parse(ctxt)
    print("SUCCESS")