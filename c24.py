from random import randint, randbytes, getrandbits
from Utils.PRNG import MT
from time import time

class MT_Cipher:
    def __init__(self, seed:int=int(time())):
        #assert seed <= (2<<16) - 1
        self.rng = MT(seed=seed)

    seed:int=int(time())

    #stream of random bytes from MT 19937
    def byte_stream(self):
        #32 bit nums --> 4 bytes
        #big or little endian? IDK. Use default i guess.
        for num in self.rng:
            yield from num.to_bytes(4)
    
    def enc(self, ptxt: bytes) -> bytes:
        #prepend random bytes before ptxt and encrypt
        ptxt = randbytes(randint(5,15)) + ptxt
        return bytes([ x^y for (x,y) in zip(ptxt, self.byte_stream())])


    def dec(self, ctxt: bytes) -> bytes:
        return bytes([ x^y for (x,y) in zip(ctxt, self.byte_stream())])




# make a 16 character password reset token
def make_token(seed:int=int(time())):
    m = MT_Cipher()
    return [next(m.byte_stream()) for _ in range(16)]

# check if a 16-byte token generated from MT19937 seeded w/ unix time
# similar to timing attack in c22
def token_from_MT(token):
    t = int(time())
    for i in range(t,t-2000,-1):
        guess = make_token(i)
        if guess == token: return True
    else: return False


def break_MT_cipher(ciphertext: bytes, known_plaintext: bytes) -> int:
    """ Brute force all 16-bit seed possibilities"""
    for seed in range(2**16):
        cipher_obj = MT_Cipher(seed=seed)
        decryption = cipher_obj.dec(ciphertext)
        if known_plaintext in decryption:
            return seed


if __name__ == '__main__':
    # BREAK MT19937 CIPHER
    real_seed = randint(0,(1<<16)-1)
    ptxt = b'A'*14
    ctxt = MT_Cipher(seed=real_seed).enc(ptxt)
    print("Breaking 16-bit MT19937 cipher")
    detected_seed = break_MT_cipher(ctxt, ptxt)
    assert detected_seed == real_seed
    print("SUCCESS\n")

    #BREAKING PASSWORD RESET TOKEN
    token = make_token()
    print("Breaking 16-byte password reset token")
    assert token_from_MT(token)
    assert not token_from_MT(randbytes(16))
    print("SUCCESS\n")
