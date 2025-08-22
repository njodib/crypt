import struct
from Utils.Hash import MD4
from random import randbytes

class Oracle:
    def __init__(self):
        self.key = randbytes(16)

    def hash(self, msg):
        return MD4(self.key + msg)

def test_MD4():
    # From RFC 1320 Appendix 5 -- Test suite

    '''
    A.5 Test suite

   The MD4 test suite (driver option "-x") should print the following
   results:

    MD4 test suite:
    MD4 ("") = 31d6cfe0d16ae931b73c59d7e0c089c0
    MD4 ("a") = bde52cb31de33e46245e05fbdbd6fb24
    MD4 ("abc") = a448017aaf21d8525fc10ae87aa6729d
    MD4 ("message digest") = d9130a8164549fe818874806e1c7014b
    MD4 ("abcdefghijklmnopqrstuvwxyz") = d79e1c308aa5bbcdeea8ed63df412da9
    MD4 ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") =
    043f8582f241db351ce627e153e7f0e4
    MD4 ("123456789012345678901234567890123456789012345678901234567890123456
    78901234567890") = e33b4ddc9c38f2199c3e7b164fcc0536
    '''
    
    ins = [
        b"", 
        b"a", 
        b"abc",
        b"message digest",
        b"abcdefghijklmnopqrstuvwxyz",
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
    ]
    outs = [
        "31d6cfe0d16ae931b73c59d7e0c089c0",
        "bde52cb31de33e46245e05fbdbd6fb24",
        "a448017aaf21d8525fc10ae87aa6729d",
        "d9130a8164549fe818874806e1c7014b",
        "d79e1c308aa5bbcdeea8ed63df412da9",
        "043f8582f241db351ce627e153e7f0e4",
        "e33b4ddc9c38f2199c3e7b164fcc0536"
    ]

    for x,y in zip(ins,outs):
        print("Message:      ", x)
        print("Expected:     ", y)
        z = MD4(x).hex()
        print("Calculated:   ", z)
        assert y==z
        print()
    
    print("SUCCESS")
    print()

def md_padding(l):
    # pad with bits 1000000000..., then store orig. length as 64-bit big-endian
    ml = l * 8
    p = b"\x80"
    p += b"\x00" * (-(l + 9) % 64)
    p += struct.pack("<Q", ml)
    return p

def forge_MD4_MAC(z:bytes,h:bytes,l:int)->bytes:
    #unpack state
    A,B,C,D = [struct.unpack('<I', h[i:i+4])[0] for i in range(0,16,4)]
    
    return MD4(z,A,B,C,D,l)

if __name__ == "__main__":
    #test_MD4() #if it doesn't throw exception it works
    
    puta = MD4(b"abc")
    A,B,C,D = [struct.unpack('<I', puta[i:i+4])[0] for i in range(0,16,4)]


    m = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    z = b";admin=true;"
    k=16

    p = md_padding(k+len(m))
    orc=Oracle()
    h = orc.hash(m)

    #illegal input allowed by oracle for validating test
    assert forge_MD4_MAC(z,h,k+len(m+p+z)) == orc.hash(m+p+z)
    print("SUCCESS")