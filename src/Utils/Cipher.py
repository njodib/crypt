from Utils.Padding import PKCS7
from Crypto.Cipher import AES
from itertools import count
from struct import pack

def count_repeat_blocks(ctxt, blocksize):
    # Split into blocks of size = blocksize. Check if any blocks are equal.
    blocks = [ctxt[i:i+blocksize] for i in range(0, len(ctxt), blocksize)]
    return len(blocks) != len(set(blocks))

def xor_data(x, y):
    return bytes([b1 ^ b2 for b1, b2 in zip(x, y)])

def detect_mode(oracle_encrypt):
    ptxt = b'X'*64
    ctxt = oracle_encrypt(ptxt)
    if count_repeat_blocks(ctxt, 16) > 0: return "ECB"
    else: return "CBC"

def detect_blocksize(oracle):
    len1 = len(oracle(b''))
    for i in count(1):
        len2 = len(oracle(b'X'*i))
        if len2 != len1:
            return len2 - len1

# Split data into blocks
def blockify(data: bytes, bs: int = 16) -> list[bytes]:
    if len(data) % bs != 0:
        raise ValueError("Data length must be multiple of block size")
    return [data[i:i+bs] for i in range(0,len(data),bs)]

# Find injection block by determining the first block which changes when 1 byte is added
def detect_injection_block(oracle):
    a = blockify(oracle(b""))
    b = blockify(oracle(b"A"))
    for inj in count(0):
        if a[inj] != b[inj]:
            return inj

# When injection block isQ totally filled, it stops changing
def detect_prefix_length(oracle):
    blocksize = detect_blocksize(oracle)
    inj = detect_injection_block(oracle)
    for pad in count(0):
        inj_short = blockify(oracle(b"A"*pad))[inj]
        inj_long = blockify(oracle(b"A"*(pad+1)))[inj]
        if inj_short == inj_long:
            return  (inj * blocksize) + (blocksize - pad)