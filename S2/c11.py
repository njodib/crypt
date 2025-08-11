from random import randint, randbytes, getrandbits
from Utils.AES import AES_ECB, AES_CBC
from c08 import blockify

def oracle(ptxt):
    ptxt = randbytes(randint(5,10)) + ptxt + randbytes(randint(5,10))
    if getrandbits(1): return AES_ECB(randbytes(16)).enc(ptxt)
    else: return AES_CBC(randbytes(16), randbytes(16)).enc(ptxt)

def aes_detect_mode(oracle):
    blocks = blockify(oracle(b'X'*64)) #Ensure repeating blocks if mode is ECB
    if len(set(blocks))<len(blocks): return "ECB"
    else: return "CBC"

if __name__ == '__main__':
    #This works! So no need to test it or anything crazy.
    for i in range(10): print("FOUND:", aes_detect_mode(oracle))





