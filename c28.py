from base64 import b64encode, b64decode
import struct
import hashlib
from random import randint


def left_rotate(num: int, shift:int):
    return ((num<<shift) | (num >>(32-shift))) & 0xffffffff

def sha1(msg: bytes):
    #INITIAL HASH VALUES
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    #PREPROCESS
    ml = 8*len(msg)
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

test_1 = b"abc"
print("SINGLE BLOCK HASH:", sha1(test_1).hex())
assert sha1(test_1).hex() == hashlib.sha1(test_1).digest().hex()

test_2 = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
print("MULTIPLE BLOCK HASH:", sha1(test_2).hex())
assert sha1(test_2).hex() == hashlib.sha1(test_2).digest().hex()

print("TESTS SUCCESSFUL")