from random import randbytes, randint
from utils import pkcs7_pad, aes_ecb_encrypt
from base64 import b64decode
from math import ceil


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
    len1 = len(enc(b""))
    bs = 1
    len2 = len(enc(b"A"*bs))
    while len1 == len2:
        bs += 1
        len2 = len(enc(b"A"*bs))
    block_size = len2-len1

    #find injection block
    injection_block = 0
    while True:
        a = enc(b"")[injection_block * block_size : (injection_block+1) * block_size]
        b = enc(b"A")[injection_block * block_size : (injection_block+1) * block_size]
        if a == b:
            injection_block += 1
        else:
            break

    #find prefix length
    prefix_length = 0
    while True:
        inj_short = enc(b"A"*prefix_length)[injection_block * block_size : (injection_block+1) * block_size]
        inj_long = enc(b"A"*(prefix_length+1))[injection_block * block_size : (injection_block+1) * block_size]
        if inj_short == inj_long:
            break
        else:
            prefix_length += 1
    prefix_length = (injection_block * block_size) + (block_size - prefix_length)
    
    #postfix length
    postfix_length = len1 - prefix_length - (bs-1)

    #blocksize, amount of bytes for unpadded, prefix length, postfix length
    return block_size, bs-1, injection_block, prefix_length, postfix_length

block_size, unpad_size, inj_block, pre_size, post_size = get_encryption_details()


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
