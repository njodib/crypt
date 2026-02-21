from random import randbytes
from Utils.AES import AES_CBC
from Utils.Cipher import detect_prefix_length, detect_blocksize

def xor(x: bytes, y:bytes):
    return bytes (xb^yb for xb,yb in zip(x,y))


class Oracle:
    def __init__(self):
        self.iv = randbytes(16)
        self.key = randbytes(16)
        self.pre = b"comment1=cooking%20MCs;userdata="
        self.post = b";comment2=%20like%20a%20pound%20of%20bacon"
        self.cipher = AES_CBC(self.key, self.iv)

    def encode(self, user_input: bytes):
        ptxt = user_input.replace(b';', b'').replace(b'=', b'')
        ptxt = self.pre + ptxt + self.post
        ctxt = self.cipher.encrypt(ptxt)
        return ctxt

    def parse(self, ctxt):
        data = self.cipher.decrypt(ctxt)
        return b';admin=true' in data

def cbc_bit_flip(encryption_oracle):
    """Performs a CBC bit flipping attack to accomplish admin privileges in the decrypted data."""
    # Get blocksize
    blocksize = detect_blocksize(encryption_oracle)

    # Get prefix length. Align prefix to end of next block with prepadding
    prefix_length = detect_prefix_length(encryption_oracle)
    prefix_padding_length = -prefix_length % blocksize
    l = prefix_length + prefix_padding_length

    # Get plaintext length, Align to end of block with prepadding.
    ptxt = b"?????9admin9true"
    ptxt_padding_length = -len(ptxt) % blocksize
    final_plaintext = ptxt_padding_length * b'?' + ptxt

    # Make the plaintext long one block_length and encrypt it
    ctxt = encryption_oracle(prefix_padding_length * b'?' + ptxt)
    return ctxt[:l - 11] + \
        bytes([ctxt[l-11] ^ ord('9') ^ ord(';')]) + \
        ctxt[l - 10: l - 5] + \
        bytes([ctxt[l - 5] ^ ord('9') ^ ord('=')]) + \
        ctxt[l - 4:]



if __name__ == "__main__":
    profile = Oracle()
    assert profile.parse(cbc_bit_flip(profile.encode))