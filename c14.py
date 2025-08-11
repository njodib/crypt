from base64 import b64decode
from math import ceil
from random import randbytes, randint
from Utils.AES import AES_ECB
from c08 import blockify
from c12 import get_block_size
from c13 import get_prefix_size, get_postfix_size

class Oracle():
    def __init__(self):
        self.secret_prefix = randbytes(randint(0,69))
        self.secret_postfix = b64decode("""
            Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
            aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
            dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
            YnkK
        """)
        self.cipher = AES_ECB(randbytes(16))

    def enc(self, ptxt: bytes) -> bytes:
        ptxt = self.secret_prefix + ptxt + self.secret_postfix
        return self.cipher.enc(ptxt, pad=True)

if __name__ == "__main__":
    # Define the oracle
    oracle = Oracle().enc

    # Get encryption information
    bs = get_block_size(oracle)
    prefix_size = get_prefix_size(oracle)
    postfix_size = get_postfix_size(oracle)

    # Pad injection block (inj) to its end
    # Pad n blocks, where n is the number of blocks of postfix
    # Subtract 1 byte (we search for this one)
    inj = prefix_size//bs
    inj_pad = ((inj+1)*bs)-prefix_size
    n = ceil(postfix_size / bs)
    pad = b'A'*(inj_pad+(n*bs)-1)

    # Decrypt bytes
    ptxt = b''
    for i in range(postfix_size):
        ref = blockify(oracle(pad))[inj + n]
        for b in range(256):
            test = blockify(oracle(pad+ptxt+bytes([b])))[inj + n]
            if ref == test:
                ptxt += bytes([b])
                pad = pad[:-1]
                break
    print(ptxt.decode('utf-8'))