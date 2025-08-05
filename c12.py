from random import randbytes
from base64 import b64decode
from Utils.AES import AES_ECB
from c11 import aes_detect_mode
from itertools import count

def get_block_size(oracle):
    len1 = len(oracle(b''))
    for i in count(0):
        len2 = len(oracle(b"A"*i))
        if len2 != len1:
            return len2 - len1

def detect_msg_length(oracle) -> int:
    block_size = get_block_size(oracle)
    base_len = len(oracle(b''))
    for i in range(block_size+1):
        tmp_len = len(oracle(b'A'*i))
        if tmp_len > base_len:
            return base_len - i

#Encryption oracle
class Oracle():
    def __init__(self):
        self.key = randbytes(16)
        self.cipher = AES_ECB(self.key)
        self.unknown = b64decode(
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
            aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
            dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
            YnkK"
        )

    def enc(self, input:bytes):
        return self.cipher.enc(input + self.unknown)

if __name__ == "__main__":
    #Build encryption oracle
    enc = Oracle().enc

    #Ensure these are working correctly
    bs = get_block_size(enc)
    mode = aes_detect_mode(enc)
    assert bs == 16
    assert mode == "ECB"

    #Decryption
    ptxt = b''
    for i in range(detect_msg_length(enc)):
        pad = b'X'*(bs-1-(i%bs)) #padding ensures byte i is in last position of its block
        idx = (i // bs)*bs #index of block containing byte i
        ref = enc(pad)[idx:idx+bs]
        for b in range(256): 
            if ref == enc(pad+ptxt+bytes([b]))[idx:idx+bs]:
                ptxt += bytes([b])
                break
    print(ptxt.decode('utf-8'))