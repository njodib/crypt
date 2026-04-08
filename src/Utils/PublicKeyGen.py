#imports
from random import randint
from random import randbytes
from Utils.AES import AES_CBC
from Utils.Hash import SHA1

def modexp(b, e, m):
    # https://en.wikipedia.org/wiki/Modular_exponentiation)
    # right --> left binary
    res = 1
    b = b % m
    while e > 0:
        if e % 2 == 1:
            res = (res * b) % m
        e = e // 2
        b = (b * b) % m
    return res

class DiffieHellman:
    g_default = 2
    p_default = int('ffffffffffffffffc90fdaa22168c234c4c6628b80d'
                    'c1cd129024e088a67cc74020bbea63b139b22514a08'
                    '798e3404ddef9519b3cd3a431b302b0a6df25f14374'
                    'fe1356d6d51c245e485b576625e7ec6f44c42e9a637'
                    'ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f241'
                    '17c4b1fe649286651ece45b3dc2007cb8a163bf0598'
                    'da48361c55d39a69163fa8fd24cf5f83655d23dca3a'
                    'd961c62f356208552bb9ed529077096966d670c354e'
                    '4abc9804f1746c08ca237327ffffffffffffffff ', 16)

    def __init__(self, p=p_default, g=g_default):
        self.p = p
        self.g = g
        self.private_key = randint(1, p-1)
        self.public_key = modexp(g, self.private_key, p)

    def s(self, sender_public_key):
        return modexp(sender_public_key, self.private_key, self.p)
    
    def send(self, msg, sender_public_key):
        shared_secret = self.s(sender_public_key)
        key = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8 or 1, 'big')
        iv = randbytes(16)
        ctxt = AES_CBC(SHA1(key)[:16], iv).encrypt(msg) + iv
        # use the key to encrypt the message (not implemented here)
        return ctxt

    # This is a decryption for CTXT encrypted with AES-CBC and IV appended to end. Not general purpose.
    def receive(self, ctxt, sender_public_key):
        shared_secret = self.s(sender_public_key)
        key = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8 or 1, 'big')
        iv = ctxt[-16:] # extract the iv from the end of the ciphertext
        ptxt = AES_CBC(SHA1(key)[:16], iv).decrypt(ctxt[:-16]) # decrypt the ciphertext (excluding the iv)
        # use the key to decrypt the ciphertext (not implemented here)
        return ptxt