from random import randbytes
from utils import pkcs7_pad, decrypt_aes_ecb, aes_ecb_encrypt
from math import ceil

def strip_pkcs7_pad(padded):
    n = padded[-1]
    if n == 0 or len(padded) < n or not padded.endswith(bytes([n]*n)):
        raise ValueError("invalid padding")
    return padded[:-n]

class Profile:
    def __init__(self):
        self.key = randbytes(16)
    
    def parse(self, str):
        #kv_pairs = byte_string.split(b"&")
        #parsed = {
        #    key: value for key, value in [pair.split(b"=") for pair in kv_pairs]
        #}
        #return parsed 
        return dict(
            pair.split(b'=') for pair in str.split(b'&') 
            )
        

    def profile_for(self, email):
        if b'&' in email or b'=' in email:
            raise ValueError("Invalid")
        return b'email=' + email + b'&uid=10&role=user'

    def get_encrypted_profile(self, email):
        profile = self.profile_for(email)
        return aes_ecb_encrypt(profile, self.key)

    def get_decrypted_profile(self, ctxt):
        ptxt = strip_pkcs7_pad(decrypt_aes_ecb(ctxt, self.key))
        return self.parse(ptxt)

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
fab_email = b"nextBlockShouldSt@rt.Here:" + b"admin" + b"\x0b"*11

a = split_bytes_to_blocks(prof.profile_for(target_email), 16)
b = split_bytes_to_blocks(prof.profile_for(fab_email), 16)

cut = prof.get_encrypted_profile(fab_email)[2*16:3*16]
target = prof.get_encrypted_profile(target_email)
ctxt = target[:-16] + cut
print(ctxt)

dec = prof.get_decrypted_profile(ctxt)
print(dec)

assert dec[b'role'] == b'admin'

'''
def do_evil() -> bytes:
    prof = Profile()
    # generate a ciphertext for an admin profile
    ct_1 = prof.get_encrypted_profile(b'\x00'*10 + b'admin' + b'\x0b'*11)
    ct_2 = prof.get_encrypted_profile((b'eli@sohl.com '))
    return ct_2[:32] + ct_1[16:32]


if __name__ == "__main__":
    prof = Profile()
    # generate a ciphertext for an admin profile
    ct_1 = prof.get_encrypted_profile(b'\x00'*10 + b'admin' + b'\x0b'*11)
    ct_2 = prof.get_encrypted_profile((b'eli@sohl.com '))
    poop = ct_2[:32] + ct_1[16:32]
    print("Malicious ciphertext:", poop)
    print("Decryption:", (poop))
'''