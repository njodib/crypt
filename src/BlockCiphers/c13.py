from Utils.Cipher import AES_ECB
from Crypto import Random
from Crypto.Cipher import AES
from Utils.CookieParser import kv_encode, kv_decode
from Utils.Oracles import C13_Oracle


def ecb_cut_and_paste(encryption_oracle):
    blocksize = 16

    # block 1:           block 2 :                                           block 3: 
    # email=xxxxxxxxxx   admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b   &uid=10&role=user
    prefix_len = blocksize - len("email=")
    suffix_len = blocksize - len("admin")
    email1 = ('X' * prefix_len) + "admin" + (chr(suffix_len) * suffix_len)
    ctxt1 = encryption_oracle.encrypt(email1)

    # block 1:           block 2:           block 3: 
    # email=goop@goop.   com&uid=10&role=   user\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c
    
    # NOTE: email must be c characters where c (mod 16) = 13
    email2 = "goop@goop.com" 
    ctxt2 = encryption_oracle.encrypt(email2)

    # block 1:           block 2:           block 3:
    # email=goop@goop.   com&uid=10&role=   admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b
    ctxt_admin = ctxt2[:blocksize*2] + ctxt1[blocksize:blocksize*2]

    return ctxt_admin

if __name__ == "__main__":
    oracle = C13_Oracle()
    ctxt_admin = ecb_cut_and_paste(oracle)
    print(ctxt_admin)
    print(kv_decode(oracle.decrypt(ctxt_admin).decode()))