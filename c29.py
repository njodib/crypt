from Utils.Hash import SHA1, SHA1_MAC
from random import randbytes
import struct

# sooooo like the sha-1 hashes the messsage as a stream
#
# so if we add a key at the front, and padding at the end, the stream is like:
# k||m||p
# then we can add some new text and repad it:
# k||m||p||z||p'
# 
# but the sha-1 hash function is rly linear and iterative, so the first part is just the mac hash
# also the k||m||p length is a multiple of 512 bits, so we p much know when it will end
# 
# yay so the stream is now just h||z||p'
# bc sha-1 is super linear, we can reset the hashing state and keep iterating to get the end state


class Oracle:
    def __init__(self):
        self.key = randbytes(16)

    def hash(self, msg):
        return SHA1_MAC(msg, self.key)

# this outputs JUST the preprocess padding
# dependent only on the message length NOT msg
# msg_len given in num. of bytes
def md_padding(msg_len:int) -> bytes:
    ml = 8*msg_len
    pad = b'\x80'
    while (msg_len + len(pad)) % (512//8) != (448//8):
        pad += b'\x00'
    pad += ml.to_bytes(64//8, byteorder='big')
    # m+p is multiple of 64 bytes
    assert (msg_len + len(pad))%(512//8) == 0 
    return pad

# h is previous hash, z is bytes to 'add onto' the hash
# unpack sha1 state and build hash
def forge_SHA1_MAC(z:bytes, h:bytes, ml:int) -> bytes:
    # unpack sha-1 state and continue hashing with additional bytes from z
    h0, h1, h2, h3, h4 = [struct.unpack('>I', h[i:i+4])[0] for i in range(0,20,4)]
    #force length of 128+z = k+m+p+z as named 'length extension'
    return SHA1(z, h0, h1, h2, h3, h4, ml)#len(z)+128)



if __name__=="__main__":
    m = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    z = b";admin=true;"
    k = 16 #assume std. keylen of 16

    p = md_padding(k+len(m)) 
    orc = Oracle()
    h = orc.hash(m)

    #illegal input allowed by oracle for validating test
    assert forge_SHA1_MAC(z, h, k+len(m+p+z)) == orc.hash(m+p+z)
    print("SUCCESS")
    