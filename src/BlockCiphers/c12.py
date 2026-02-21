from Utils.Cipher import  detect_mode, detect_blocksize, decrypt_ecb_simple
from Utils.Padding import PKCS7
from Utils.Oracles import C12_Oracle
from itertools import count

def blockify(data: bytes, bs: int = 16) -> list[bytes]:
    if len(data) % bs != 0:
        raise ValueError("Data length must be multiple of block size")
    return [data[i:i+bs] for i in range(0,len(data),bs)]


#find injection block by determining the first block which changes when 1 byte is added
def get_injection_block(oracle):
    a = blockify(oracle(b""))
    b = blockify(oracle(b"A"))
    for inj in count(0):
        if a[inj] != b[inj]:
            return inj

#When injection block isQ totally filled, it stops changing
def get_prefix_size(oracle):
    blocksize = detect_blocksize(oracle)
    inj = get_injection_block(oracle)
    for pad in count(0):
        inj_short = blockify(oracle(b"A"*pad))[inj]
        inj_long = blockify(oracle(b"A"*(pad+1)))[inj]
        if inj_short == inj_long:
            return  (inj * blocksize) + (blocksize - pad)

if __name__ == '__main__':
    # Build Oracle
    oracle = C12_Oracle()

    # Determine blocksize of cipher
    blocksize = detect_blocksize(oracle)
    print("BLOCKSIZE:", blocksize, "\n")
    assert blocksize == 16

    # Determine encryption mode of cipher
    mode = detect_mode(oracle)
    print("MODE:", mode, "\n")
    assert mode == "ECB"

    # Examine appended ciphertext
    print("Interestingly, empty inputs always return the same ciphertext.")
    print("CIPHERTEXT FROM EMPTY INPUT:", oracle(b"").hex(), "\n")

    # Decrypt appended ciphertext
    ptxt_secret = decrypt_ecb_simple(oracle)
    print("DECRYPTED MESSAGE:")
    print(PKCS7(blocksize).unpad(ptxt_secret).decode().rstrip())