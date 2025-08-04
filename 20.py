#this mostly works lol

from base64 import b64decode
from Utils.BytesLogic import best_xor_key, xor, error
from typing import List
from Crypto.Cipher import AES
from struct import pack





def enc(msg):
    def ks():
        ct = 0
        cipher = AES.new(b'YELLOW SUBMARINE', AES.MODE_ECB)
        while True:
            pee = pack("QQ", 0, ct) #packs as little-endian 64-bit
            ct += 1
            yield from cipher.encrypt(pee)
    return bytes((xb^yb) for xb,yb in zip(bytearray(msg), ks()))


def guess_keystream(ciphertexts: List[bytes]) -> bytes:
    keystream_len = max(len(text) for text in ciphertexts)
    byte_vals = []
    for i in range(keystream_len):
        # i'th byte of each ciphertext long enough to have such a byte:
        ct_bytes = b''.join(bytes([text[i]]) for text in ciphertexts if i < len(text))
        concat_len = len(ct_bytes)

        best_score = float('inf')
        best_byte = None
        for j in range(256):
            guess = xor(ct_bytes, bytes([j]*concat_len))
            score = error(guess)
            if score < best_score:
                best_score = score
                best_byte = j
        assert best_byte is not None
        byte_vals.append(best_byte)
    return bytes(byte_vals)


#gets all ptxts, ctxts from 20.txt
with open('Data/20.txt') as fp:
    ctxts = [enc(b64decode(line)) for line in fp]


peepee = guess_keystream(ctxts)
print()

for text in ctxts:
    plaintext = xor(text, peepee)
    print(plaintext)
