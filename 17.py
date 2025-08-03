from random import randint, randbytes, choice
from Crypto.Cipher import AES
from Utils.Padding import pkcs7, strip_pkcs7, detect_pkcs7
from Utils.AES import aes_cbc_encrypt
from Utils.BytesLogic import xor
from base64 import b64decode, b64encode
import numpy as np


def aes_ecb_decrypt(data: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    ptxt = cipher.decrypt(data)
    return ptxt

def aes_cbc_decrypt(data:bytes, key:bytes, iv:bytes):
    bs = AES.block_size
    ptxt = b''
    prev = iv
    for i in range(0, len(data), bs):
        curr_ctxt_block = data[i:i+bs]
        dec_block = aes_ecb_decrypt(curr_ctxt_block, key)
        ptxt += xor(prev, dec_block)
        prev = curr_ctxt_block
    return ptxt




BLOCK_SIZE = 16
key = randbytes(16)
iv = randbytes(BLOCK_SIZE)

strings = [
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

def bytes_to_chunks(x: bytes, chunksize:int):
    return [x[i: i+chunksize] for i in range(0, len(x), chunksize)]

def enc(i:int) -> bytes:
    s = strings[i]#choice(strings)
    return aes_cbc_encrypt(pkcs7(s, BLOCK_SIZE), key, iv)

def dec(orc_iv: bytes, ciphertext:bytes) -> bytes:
    return aes_cbc_decrypt(ciphertext, key, orc_iv)


def padding_oracle(iv: bytes, ciphertext:bytes) -> bool:
    plaintext = dec(iv, ciphertext)
    try:
        strip_pkcs7(plaintext)
    except ValueError:
        return False
    return True


def single_block_attack(orc_iv: bytes, block: bytes, oracle) -> bytes:
    plaintext = b''
    zeroing_iv = [0]*BLOCK_SIZE

    for pad_len in range(1, BLOCK_SIZE+1):
        padding_iv = [pad_len ^ b for b in zeroing_iv]

        for candidate in range(256):
            padding_iv[-pad_len] = candidate
            new_iv = bytes(padding_iv)

            if oracle(new_iv, block):
                if pad_len == 1:
                    padding_iv[-2] ^=1
                    new_iv = bytes(padding_iv)
                    if not padding_oracle(new_iv, block):
                        continue
                plaintext = bytes([candidate ^ pad_len]) + plaintext
                break
        else:
            raise Exception("No match found :(")

        zeroing_iv[-pad_len] = candidate ^ pad_len
    
    return xor(plaintext, orc_iv)

def padding_oracle_attack(ciphertext:bytes, oracle) -> bytes:
    plaintext = b''
    block_iv = iv
    blocks = bytes_to_chunks(ciphertext, BLOCK_SIZE)
    
    for i, block in enumerate(blocks):
        plaintext += single_block_attack(block_iv, block, oracle)
        block_iv = block
    
    if detect_pkcs7(plaintext):
        return strip_pkcs7(plaintext)
    else:
        return plaintext

if __name__ == "__main__":
    for i in range(10):
        ciphertext = enc(i)
        plaintext = padding_oracle_attack(ciphertext, padding_oracle)
        print(b64decode(plaintext).decode())