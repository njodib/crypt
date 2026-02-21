from Crypto.Cipher import AES
from Utils.Padding import PKCS7
from Utils.BytesLogic import xor, xor_fixed
from struct import pack

class AES_ECB():
    def __init__(self, key:bytes):
        self.cipher = AES.new(key, AES.MODE_ECB)

    def decrypt(self, data):
        return PKCS7(16).unpad(self.cipher.decrypt(data))

    def encrypt(self, data):
        return self.cipher.encrypt(PKCS7(AES.block_size).pad(data))

class AES_CBC():
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv

    def encrypt(self, data):
        """Encrypts the given data with AES-CBC, using the given key and iv."""
        ciphertext = b''
        prev = self.iv
        ecb_enc = AES_ECB(self.key).encrypt

        # Process the encryption block by block
        for i in range(0, len(data), AES.block_size):

            # Always PKCS 7 pad the current plaintext block before proceeding
            curr_plaintext_block = PKCS7(AES.block_size).pad(data[i:i + AES.block_size])
            block_cipher_input = xor_fixed(curr_plaintext_block, prev)
            encrypted_block = ecb_enc(block_cipher_input)
            ciphertext += encrypted_block
            prev = encrypted_block

        return ciphertext

    def decrypt(self, data, unpad=True):
        plaintext = b''
        prev = self.iv
        ecb_dec = AES_ECB(self.key).decrypt

        # Process the decryption block by block
        for i in range(0, len(data), AES.block_size):
            curr_ciphertext_block = data[i:i + AES.block_size]
            decrypted_block = ecb_dec(curr_ciphertext_block)
            plaintext += xor_fixed(prev, decrypted_block)
            prev = curr_ciphertext_block

        # Return the plaintext either unpadded or left with the padding depending on the unpad flag
        return PKCS7(AES.block_size).unpad(plaintext) if unpad else plaintext

class AES_CTR:
    def __init__(self, key, nonce=0):
        self.key = key
        self.nonce = nonce

    def keystream(self):
        ct = 0
        cipher = AES.new(self.key, AES.MODE_ECB)
        while True:
            pee = pack("QQ", self.nonce, ct) #packs as little-endian 64-bit
            ct += 1
            yield from cipher.encrypt(pee)

    def decrypt(self, s):
        return bytes((xb^yb) for xb,yb in zip(bytearray(s), self.keystream()))

    encrypt = decrypt
