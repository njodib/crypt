# IMPORTANT
# If IV is given to the user, the entire plaintext can be decrypted
# If IV is unknown, the first block cannot be decrypted

# TODO: Break padding oracle w/o given IV

from random import  randbytes, choice
from Utils.AES import AES_CBC
from S1.c02 import xor_bytes
from Utils.Padding import detect_pkcs7, strip_pkcs7
from base64 import b64decode

class Oracle():
    def __init__(self):
        BLOCKSIZE = 16
        self.key = randbytes(16)
        self.iv = randbytes(16)
        self.cipher = AES_CBC(self.key, self.iv)
        self.strings = [
            b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
            b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
            b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
            b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
            b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
            b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
            b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
            b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
            b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
            b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
        ]
    
    def enc(self):
        s = choice(self.strings)
        ctxt = self.cipher.enc(s, pad=True)
        return ctxt, self.iv

    def dec(self, ctxt):
        try: AES_CBC(self.key, self.iv).dec(ctxt, strip=True)
        except ValueError: return False
        else: return True

def decrypt_block_mask(oracle: Oracle, current_block: bytes) -> bytes:
    # initialize empty mask
    mask = bytearray(16)

    # decrypt byte at a time from end to start
    for byte_idx in range(16-1, -1, -1):
        # build previous block
        pad_value = 16 - byte_idx
        last_block = bytearray(xor_bytes(bytes([pad_value] * 16), mask))

        # iterate values until the padding is correct
        for byte_val in range(256):
            last_block[byte_idx] = byte_val
            sequence = last_block + current_block
            if oracle(sequence):
                mask[byte_idx] = byte_val ^ pad_value
                break
    return mask


def attack(padding_oracle, ct, iv):
    msg = iv + ct
    blocks = [msg[i:i+16] for i in range(0, len(msg), 16)]
    result = b''

    # loop over pairs of consecutive blocks
    iv = blocks[0]
    for ct in blocks[1:]:
        dec = decrypt_block_mask(padding_oracle, ct)
        pt = bytes(iv_byte ^ dec_byte for iv_byte, dec_byte in zip(iv, dec))
        result += pt
        iv = ct

    return result

if __name__ == "__main__":
    orc = Oracle()
    for i in range(25):
        ct, iv = orc.enc()
        result = attack(orc.dec, ct, iv)
        if detect_pkcs7(result):plaintext = strip_pkcs7(result)
        else: plaintext = result
        print("Trial", i, "--", b64decode(plaintext).decode('utf-8'))
