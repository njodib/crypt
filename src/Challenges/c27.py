from Utils.AES import AES_CBC
from Utils.BytesLogic import xor_fixed
from Utils.Oracles import C27_Oracle

if __name__ == '__main__':
    # Setup ctxt with >3 blocks
    oracle = C27_Oracle()
    ctxt = bytearray(oracle.encode(b'A'*(3*16)))
    
    # Parse (C1,0,C1,...)
    ctxt[16:2*16] = bytes([0]*16) 
    ctxt[2*16:3*16] = ctxt[:16]
    try: oracle.parse(ctxt)
    except ValueError as e: decrypted = e.args[1] #expect error from 0s block
    key = xor_fixed(decrypted[:16], decrypted[2*16:3*16]) #P1 xor P3
    
    # With the key, we read a decrypted ciphertext
    ciphertext = oracle.encode(b'____SUCCESSFUL DECRYPTION____')
    print(AES_CBC(key, key).decrypt(ciphertext))