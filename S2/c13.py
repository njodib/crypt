from random import randbytes
from Utils.Padding import pkcs7
from Utils.AES import AES_ECB
from c08 import blockify
from c12 import detect_msg_length, get_block_size

def get_injection_block(oracle):
    #find injection block by determining the first block which changes when 1 byte is added
    a = blockify(oracle(b""))
    b = blockify(oracle(b"A"))
    inj = 0
    while a[inj] == b[inj]: inj += 1
    return inj

def get_prefix_size(oracle):
    block_size = get_block_size(oracle)
    inj = get_injection_block(oracle)

    #When injection block is filled with padding, it stops changing
    inj_pad = 0
    while True:
        inj_short = blockify(oracle(b"A"*inj_pad))[inj]
        inj_long = blockify(oracle(b"A"*(inj_pad+1)))[inj]
        if inj_short == inj_long:
            break
        inj_pad += 1
    prefix_length = (inj * block_size) + (block_size - inj_pad)
    return prefix_length

def get_postfix_size(oracle):
    bs = get_block_size(oracle)
    pref = get_prefix_size(oracle)
    msg = detect_msg_length(oracle)
    end_padding = bs - (msg % bs)
    post = len(oracle(b"")) - pref - end_padding
    return post

class Profile:
    def __init__(self):
        self.key = randbytes(16)
        self.user = {}
    
    @staticmethod
    def kv_parse(cookie:bytes) -> dict:
        s = cookie.decode('utf-8')
        return dict(pair.split('=') for pair in s.split('&'))

    @staticmethod
    def profile_for(email: bytes) -> bytes:
        if b'&' in email or b'=' in email: raise ValueError("Invalid")
        #email = email.replace('&', '').replace('=', '')
        return b'email='+email+b'&uid=10&role=user'

    #Email -> Update profile -> Return ciphertext
    def enc(self, email: str) -> bytes:
        profile = self.profile_for(email)
        return AES_ECB(self.key).enc(profile, pad=True)

    #Encrypted profile
    def dec(self, ctxt: bytes):
        ptxt = AES_ECB(self.key).dec(ctxt, strip=True)
        return self.kv_parse(ptxt)

# U could just inspect the cookie too.
# But this code generalizes to any cookie
if __name__ == "__main__":
    # Define the encryption oracle
    prof = Profile()
    oracle = prof.enc

    # Encryption information from oracle
    bs = get_block_size(oracle)
    msg_len = detect_msg_length(oracle)
    inj = get_injection_block(oracle)
    pre = get_prefix_size(oracle)
    post = get_postfix_size(oracle)

    # Fill the injection block with Xs
    # Encrypt padded 'admin' block
    fake_email_len = ((inj+1)*16)-pre
    fake_email = (b'X'*fake_email_len) + pkcs7(b'admin', bs)
    admin_ctxt = oracle(fake_email)[(inj+1)*bs:(inj+2)*bs]

    # Align 'user' to last block.
    # Replace this with the padded 'admin' block
    admin_email_len = bs - ((len(prof.profile_for(b''))-len('user'))%bs)
    admin_email = b"X"*admin_email_len #Any 13 char email
    ctxt = oracle(admin_email)[:-bs] + admin_ctxt

    # Test and print
    dec = prof.dec(ctxt)
    print(dec)
    assert dec['role'] == 'admin'