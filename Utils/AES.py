from Crypto.Cipher import AES
from Utils.Padding import pkcs7, strip_pkcs7
from Utils.BytesLogic import xor

def aes_ecb_encrypt(data: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pkcs7(data, AES.block_size))

def aes_cbc_encrypt(data:bytes, key:bytes, iv:bytes):
    bs = AES.block_size
    ctxt = b''
    prev = iv

    for i in range(0, len(data), bs):
        curr_ptxt_block = pkcs7(data[i:i + bs], bs)
        block_cipher_input = xor(curr_ptxt_block, prev)
        enc_block = aes_ecb_encrypt(block_cipher_input, key)
        ctxt += enc_block
        prev = enc_block
    return ctxt

def aes_ecb_decrypt(data: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    return strip_pkcs7(cipher.decrypt(data))

def aes_cbc_decrypt(data:bytes, key:bytes, iv:bytes):
    bs = AES.block_size
    ptxt = b''
    prev = iv
    for i in range(0, len(data), bs):
        curr_ctxt_block = data[i:i+bs]
        dec_block = aes_ecb_decrypt(curr_ctxt_block, key)
        ptxt += xor(prev, dec_block)
        prev = curr_ctxt_block
    return strip_pkcs7(ptxt)
