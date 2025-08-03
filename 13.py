from random import randbytes
from utils import pkcs7_pad, decrypt_aes_ecb, aes_ecb_encrypt
from math import ceil


class Profile:
    def __init__(self):
        self.key = randbytes(16)
    
    def parse(self, byte_string):
        str = byte_string.decode('utf-8')
        res = dict(pair.split('=') for pair in str.split('&'))
        return res

    def profile_for(self, email):
        if b'&' in email or b'=' in email:
            raise ValueError("Invalid")
        return b'email=' + email + b'&uid=10&role=user'

    def get_encrypted_profile(self, email):
        profile = self.profile_for(email)
        return aes_ecb_encrypt(profile, self.key)

    def get_decrypted_profile(self, ctxt):
        profile = decrypt_aes_ecb(ctxt, self.key)
        return self.parse(profile)

    def get_aes_key(self):
        return self.key

def split_bytes_to_blocks(x, blocksize):
    nb_blocks = ceil(len(x)/blocksize)
    return [x[blocksize*i:blocksize*(i+1)] for i in range(nb_blocks)]



prof = Profile()
poop = prof.profile_for(b"email@example.com")
print(poop)

assert prof.profile_for(b"foo@bar.com") == b"email=foo@bar.com&uid=10&role=user"

block_size = 16

#gets 'user' as separate block
target_email = b"eeeeeeeeeeeemail@attacker.com"
fab_email = b"nextBlockShouldSt@rt.Here:" + pkcs7_pad(b"admin", 16)

a = split_bytes_to_blocks(prof.profile_for(target_email), 16)
b = split_bytes_to_blocks(prof.profile_for(fab_email), 16)

cut = prof.get_encrypted_profile(fab_email)[2*16:3*16]
target = prof.get_encrypted_profile(target_email)
ctxt = target[:-16] + cut
print(ctxt)

dec = prof.get_decrypted_profile(ctxt)
print(dec)
