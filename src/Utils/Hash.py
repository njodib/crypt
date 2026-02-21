#from base64 import b64encode, b64decode
import struct
#import hashlib
#from random import randint

from Utils.BytesLogic import xor
from collections.abc import Callable

def left_rotate(num: int, shift:int):
    return ((num<<shift) | (num >>(32-shift))) & 0xffffffff

def SHA1(msg: bytes, h0=None, h1=None, h2=None, h3=None, h4=None, ml=None):
    #INITIAL HASH VALUES
    if not h0: h0= 0x67452301
    if not h1: h1 = 0xEFCDAB89
    if not h2: h2 = 0x98BADCFE
    if not h3: h3 = 0x10325476
    if not h4: h4 = 0xC3D2E1F0

    #PREPROCESS
    if not ml: ml = 8*len(msg)
    else: ml *= 8
    #append '1' to message
    msg += b'\x80'
    # append bits '0' until msg bit-length is congruent to -64 = 448 (mod 512)
    while len(msg) % (512//8) != (448//8):
        msg += b'\x00'
    #append ml as 64-bit big-endian integer
    msg += ml.to_bytes(64//8, byteorder='big')
    assert len(msg)%(512//8) == 0

    #chunk into 512-bit pieces (64 bytes)
    chunks = []
    for i in range(0,len(msg),64):
        chunks += [msg[i:i+64]]
 
    for chunk in chunks:
        #build and iterate 32 bit (4 byte) words from chunk
        w = [int.from_bytes(chunk[i:i+4], byteorder='big') for i in range(0, 64, 4)]
 
        #word 17 -> 80 is computed recursivelyt
        for i in range(16,80):
            w += [left_rotate(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1)]
        
        #main loop: mystery math
        a,b,c,d,e = h0,h1,h2,h3,h4
        for i in range(0, 80):
            if 0<=i<=19:
                f = (b&c)|((~b)&d)
                k = 0x5A827999
            elif 20<=i<=39:
                f = b^c^d
                k = 0x6ED9EBA1
            elif 40<=i<=59:
                f = (b&c)^(b&d)^(c&d) 
                k = 0x8F1BBCDC
            elif 60<=i<=79:
                f = b^c^d
                k = 0xCA62C1D6
            
            temp = (left_rotate(a,5) + f + e + k + w[i])&0xffffffff
            
            a,b,c,d,e = temp,a,left_rotate(b,30),c,d
            #print("XX",i,hex(a),hex(b),hex(c),hex(d),hex(e))

        # CHUNKS HASH RESULTS SO FAR
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    #final hash value
    hh = b''.join(struct.pack('>I', i) for i in [h0, h1, h2, h3, h4])
    return hh

def SHA1_MAC(msg, key):
    return SHA1(key + msg)

# Implemented from https://www.ietf.org/rfc/rfc1320.txt
def MD4 (m: bytes,A=None,B=None,C=None,D=None,ml=None):
    # pad with bits 1000000000..., then store orig. length as 64-bit big-endian
    if not ml: ml = len(m)
    m += b"\x80"
    m += b"\x00" * (-(ml + 9) % 64)
    m += struct.pack("<Q", ml*8)

    # magic numbers
    if not A: A = 0x67452301
    if not B: B = 0xEFCDAB89
    if not C: C = 0x98BADCFE
    if not D: D = 0x10325476

    # process each 512-bit (64 byte) chunk
    #chunks = [m[i: i + 64] for i in range(0, len(m), 64)]
    chunks = []
    while m:
        chunks += [m[:64]]
        m = m[64:]
    for chunk in chunks:
        #unpack chunk 64-byte chunk into 16 4-byte words
        X = list(struct.unpack('<'+'I'*16, chunk))

        #store magic numbers
        AA = A
        BB = B
        CC = C
        DD = D

        # round 1
        lrot = lambda x, n: ((x << n)&0xFFFFFFFF) | (x >> (32 - n))
        F = lambda x, y, z: ((x & y) | (~x & z))
        FF = lambda a,b,c,d,k,s: lrot((a + F(b,c,d) + X[k]) & 0xFFFFFFFF, s)
        
        A = FF(A,B,C,D,0,3)
        D = FF(D,A,B,C,1,7)
        C = FF(C,D,A,B,2,11)
        B = FF(B,C,D,A,3,19)

        A = FF(A,B,C,D,4,3)
        D = FF(D,A,B,C,5,7)
        C = FF(C,D,A,B,6,11)
        B = FF(B,C,D,A,7,19)

        A = FF(A,B,C,D,8,3)
        D = FF(D,A,B,C,9,7)
        C = FF(C,D,A,B,10,11)
        B = FF(B,C,D,A,11,19)

        A = FF(A,B,C,D,12,3)
        D = FF(D,A,B,C,13,7)
        C = FF(C,D,A,B,14,11)
        B = FF(B,C,D,A,15,19)

        # round 2
        G = lambda x, y, z: ((x & y) | (x & z) | (y & z))
        GG = lambda a,b,c,d,k,s: lrot((a + G(b,c,d) + X[k] + 0x5A827999) & 0xFFFFFFFF, s)

        A = GG(A,B,C,D,0,3)
        D = GG(D,A,B,C,4,5)
        C = GG(C,D,A,B,8,9)
        B = GG(B,C,D,A,12,13)

        A = GG(A,B,C,D,1,3)
        D = GG(D,A,B,C,5,5)
        C = GG(C,D,A,B,9,9)
        B = GG(B,C,D,A,13,13)

        A = GG(A,B,C,D,2,3)
        D = GG(D,A,B,C,6,5)
        C = GG(C,D,A,B,10,9)
        B = GG(B,C,D,A,14,13)

        A = GG(A,B,C,D,3,3)
        D = GG(D,A,B,C,7,5)
        C = GG(C,D,A,B,11,9)
        B = GG(B,C,D,A,15,13)

        # round 3
        H = lambda x, y, z: (x^y^z)
        HH = lambda a,b,c,d,k,s: lrot((a + H(b,c,d) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)

        A = HH(A,B,C,D,0,3)
        D = HH(D,A,B,C,8,9)
        C = HH(C,D,A,B,4,11)
        B = HH(B,C,D,A,12,15)

        A = HH(A,B,C,D,2,3)
        D = HH(D,A,B,C,10,9)
        C = HH(C,D,A,B,6,11)
        B = HH(B,C,D,A,14,15)

        A = HH(A,B,C,D,1,3)
        D = HH(D,A,B,C,9,9)
        C = HH(C,D,A,B,5,11)
        B = HH(B,C,D,A,13,15)

        A = HH(A,B,C,D,3,3)
        D = HH(D,A,B,C,11,9)
        C = HH(C,D,A,B,7,11)
        B = HH(B,C,D,A,15,15)

        #add stored magic numbers to end result
        A = (A + AA) & 0xFFFFFFFF
        B = (B + BB) & 0xFFFFFFFF
        C = (C + CC) & 0xFFFFFFFF
        D = (D + DD) & 0xFFFFFFFF

    #convert to little endian, pack, and return :)
    A = A.to_bytes(4, byteorder='little')
    B = B.to_bytes(4, byteorder='little')
    C = C.to_bytes(4, byteorder='little')
    D = D.to_bytes(4, byteorder='little')
    return A+B+C+D



class HMAC:
    @staticmethod
    def _compute_block_sized_key(key: bytes, hash_func: Callable[[bytes], bytes], block_size: int):
        # Keys longer than [block_size] are shortened by hashing them
        if len(key) > block_size:
            key = hash_func(key)

        # Keys shorter than [block_size] are padded to [block_size] by padding with zeros on the right
        if len(key) < block_size:
            return key + bytes(block_size - len(key))

        return key

    @classmethod
    def _process(cls, key: bytes, msg: bytes, hash_func: Callable[[bytes], bytes], block_size: int):
        # Compute the block sized key
        block_sized_key = cls._compute_block_sized_key(key, hash_func, block_size)

        # Outer & Inner padded key
        o_key_pad = xor(block_sized_key, bytes([0x5c] * block_size))
        i_key_pad = xor(block_sized_key, bytes([0x36] * block_size))

        # calc hash
        return hash_func(o_key_pad + hash_func(i_key_pad + msg))

    @classmethod
    def sha1(cls, key: bytes, msg: bytes):
        hash_func = SHA1
        block_size = 64
        return cls._process(key=key, msg=msg, hash_func=hash_func, block_size=block_size)



'''
test_1 = b"abc"
print("SINGLE BLOCK HASH:", sha1(test_1).hex())
assert sha1(test_1).hex() == hashlib.sha1(test_1).digest().hex()

test_2 = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
print("MULTIPLE BLOCK HASH:", sha1(test_2).hex())
assert sha1(test_2).hex() == hashlib.sha1(test_2).digest().hex()

print("TESTS SUCCESSFUL")
'''