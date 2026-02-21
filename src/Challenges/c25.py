from Utils.Oracles import C25_Oracle

if __name__ == "__main__":
    # setup oracle
    oracle = C25_Oracle()

    # ciphertext given by calling the zero-change edit
    ctxt = oracle.edit(0,'')

    # symmetric cipher ==> encryption and decryption handled similarly. "encrypting" ciphertext == decrypting plaintext
    ptxt = oracle.edit(0, ctxt)
    print(ptxt.decode())