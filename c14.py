from random import randbytes, randint
from utils import pkcs7_pad, aes_ecb_encrypt
from base64 import b64decode
from math import ceil
from c08 import blockify
from c12 import get_block_size, detect_msg_length
from itertools import count
from c13 import get_injection_block, get_prefix_size, get_postfix_size

_key = randbytes(16)
_secret_prefix = randbytes(randint(0,69))

_secret_postfix = b64decode("""
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
YnkK
""")

def enc(ptxt: bytes) -> bytes:
    ptxt = _secret_prefix + ptxt + _secret_postfix
    return aes_ecb_encrypt(pkcs7_pad(ptxt, 16), _key)

def get_encryption_details():
    block_size = get_block_size(enc)
    inj = get_injection_block
    prefix_length = get_prefix_size(enc)
    postfix_length = get_postfix_size(enc)
    return block_size, inj, prefix_length, postfix_length


if __name__ == "__main__":
    block_size = get_block_size(enc)
    inj_block = get_injection_block(enc)
    pre_size = get_prefix_size(enc)
    post_size = get_postfix_size(enc)

    #text to fill prefix block(s)
    
    ptxt_prefix = (b'X'*(((inj_block+1)*block_size)-pre_size))

    #Add n ptxt blocks under the n secret post-fix block(s)
    n = ceil(post_size / block_size)
    ptxt_test = b"A"*((n*block_size))

    top = inj_block + n
    ptxt = ptxt_prefix + ptxt_test


    found_bytes = b''

    for _ in range(post_size):
        ptxt_test = ptxt_test[1:]
        ptxt = ptxt_prefix + ptxt_test
        hii = enc(ptxt)[top*block_size : (top+1)*block_size]

        for b in range(256):
            puta = enc(ptxt+found_bytes+bytes([b]))[top*block_size : (top+1)*block_size]
            if puta == hii:
                found_bytes += bytes([b])
                break
    print(found_bytes.decode('utf-8'))