from Utils.Padding import PKCS7
from Utils.Cipher import blockify
from Utils.Oracles import C17_Oracle

def crack(ctxt, valid_ctxt):
    decrypted = bytes()
    prev = oracle.iv
    for curr in blockify(ctxt, 16):
        ptxt = bytearray(oracle.iv)
        test = bytearray(prev)
        # Corrupt each byte of block: right to left
        for p in range(1, 17, 1):
            # Increment known bytes by 1 to prepare for corrupting next byte into valid decryption
            for k in range(1, p):
                test[-k] = p ^ ptxt[-k] ^ prev[-k]
            # Check every possible byte. One of these produces a valid padding.
            for _ in range(0,256):
                # We increment NOT substitute.
                # Otherwise existing padding counts as valid and the last block gets effed up.
                test[-p] = (test[-p] + 1) % 256
                # Check if corrupted byte produces valid decryption
                if(valid_ctxt(bytes(test) + curr)):
                    # C_i = E(P_i xor C_{i-1})
                    # D(C_i) = P_i xor C_{i-1} ==> P_i = D(C_i) xor C_{i-1}
                    # Take new random X block and concatenate to left end of C_i. Call this X,C_i which decrypts to P_0',P_1'
                    # P_1' = D(C_i) xor X ==> P_1' = P_i xor C_{i-1} xor X ==> P_i = P_1' xor C_{i-1} xor X
                    # X is constructed, C_0 is IV, P_1' is calculated
                    ptxt[-p] = test[-p] ^ prev[-p] ^ p
                    break
        decrypted += bytes(ptxt)
        prev = curr
    print(PKCS7().unpad(decrypted))

if __name__ == '__main__':
    for _ in range(24):
        oracle = C17_Oracle()
        ctxt = oracle.get_encrypted_message()
        #print(ctxt)
        crack(ctxt, oracle.valid_ctxt)