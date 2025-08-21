from Utils.Hash import SHA1, SHA1_MAC
from random import randbytes
import struct

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
    assert (msg_len + len(pad))%(512//8) == 0
    return pad

# unpack sha1 state and build hash
def forge_SHA1_MAC(new_msg, real_mac: bytes, fake_len: int):
    h0, h1, h2, h3, h4 = [struct.unpack('>I', real_mac[i:i+4])[0] for i in range(0,20,4)]
    return SHA1(new_msg, h0, h1, h2, h3, h4, fake_len)

if __name__=="__main__":
    # create SHA-1 keyed MAC on original message
    orc = Oracle()
    real_msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    real_mac = orc.hash(real_msg)

    # info for forged SHA-1 MAC
    key_len = 16 # no access to key ==> guess std. key length
    new_msg = b";admin=true;"

    # forge hash
    fake_msg = real_msg + md_padding(key_len + len(real_msg)) + new_msg
    print(f'{fake_msg=}')

    fake_len = key_len + len(fake_msg)
    fake_mac = forge_SHA1_MAC(new_msg, real_mac, fake_len)
    print("FAKE MAC:",fake_mac.hex())

    # check validity of fake MAC by comparing with real, keyed hash
    print("REAL MAC:",orc.hash(fake_msg).hex())
    assert fake_mac == orc.hash(fake_msg)
    print("SUCCESS")
    