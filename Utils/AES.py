from Crypto.Cipher import AES
from Utils.Padding import pkcs7, strip_pkcs7, detect_pkcs7
from Utils.BytesLogic import xor
from random import randbytes
from struct import pack

def aes_ecb_encrypt(data: bytes, key: bytes, pad=True):
    cipher = AES.new(key, AES.MODE_ECB)
    if pad: return cipher.encrypt(pkcs7(data, AES.block_size))
    else: return cipher.encrypt(data, AES.block_size)

def aes_ecb_decrypt(data: bytes, key: bytes, strip=True):
    cipher = AES.new(key, AES.MODE_ECB)
    if strip: return strip_pkcs7(cipher.decrypt(data))
    else: return cipher.decrypt(data)


        



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



def aes_cbc_decrypt(data:bytes, key:bytes, iv:bytes, strip=True):
    bs = AES.block_size
    ptxt = b''
    prev = iv
    for i in range(0, len(data), bs):
        curr_ctxt_block = data[i:i+bs]
        dec_block = aes_ecb_decrypt(curr_ctxt_block, key)
        ptxt += xor(prev, dec_block)
        prev = curr_ctxt_block
    if strip: return strip_pkcs7(ptxt)
    else: return ptxt


class AES_ECB:
    def __init__(self, key):
        self.key = key

    def enc(self, ptxt: bytes, pad=True):
        cipher = AES.new(self.key, AES.MODE_ECB)
        if pad: return cipher.encrypt(pkcs7(ptxt, AES.block_size))
        else: return cipher.encrypt(ptxt, AES.block_size)

    def dec(self, ctxt: bytes, strip=True):
        cipher = AES.new(self.key, AES.MODE_ECB)
        if strip: return strip_pkcs7(cipher.decrypt(ctxt))
        else: return cipher.decrypt(ctxt)

class AES_CBC:
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv

    def enc(self, data:bytes, pad=True):
        bs = AES.block_size
        ctxt = b''
        prev = self.iv

        for i in range(0, len(data), bs):
            curr_ptxt_block = pkcs7(data[i:i + bs], bs)
            block_cipher_input = xor(curr_ptxt_block, prev)
            cipher = AES.new(self.key, AES.MODE_ECB)
            enc_block = cipher.encrypt(block_cipher_input)
            ctxt += enc_block
            prev = enc_block
        
        if pad: return pkcs7(ctxt, bs)
        else: return ctxt

    def dec(self, data:bytes, strip=True):
        bs = AES.block_size
        ptxt = b''
        prev = self.iv
        for i in range(0, len(data), bs):
            curr_ctxt_block = data[i:i+bs]
            cipher = AES.new(self.key, AES.MODE_ECB)
            dec_block = cipher.decrypt(curr_ctxt_block)
            ptxt += xor(prev, dec_block)
            prev = curr_ctxt_block

        if strip: 
            try: detect_pkcs7
            except: return ptxt
            return strip_pkcs7(ptxt)
        else: return ptxt

class AES_CTR:
    def __init__(self, key, nonce):
        self.key = key
        self.nonce = nonce

    def dec(self, s):
        def ks():
            ct = 0
            cipher = AES.new(self.key, AES.MODE_ECB)
            while True:
                pee = pack("QQ", self.nonce, ct) #packs as little-endian 64-bit
                ct += 1
                yield from cipher.encrypt(pee)
        return bytes((xb^yb) for xb,yb in zip(bytearray(s), ks()))

    enc = dec
