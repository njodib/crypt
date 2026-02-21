from Utils.Cipher import detect_blocksize, detect_prefix_length

def decrypt_ecb_simple(oracle):
    blocksize = detect_blocksize(oracle)
    known = b''
    # examine each byte of unknown appended text
    for _ in range(len(oracle(b''))):
        # in Z_{blocksize}, [len(prefix)] + [len(known)] = [blocksize - 1] = [-1]
        prefix = b'X' * (-(len(known)+1) % blocksize)
        # real ciphertext
        ctxt = oracle(prefix)[:len(prefix) + len(known) + 1]
        for b in range(256):
            # ciphertext using byte 'b' as last known
            test = oracle(prefix + known + bytes([b]))[:len(prefix) + len(known) + 1]
            if ctxt == test:
                known += bytes([b])
                break
    return known

# NOTE: This decryption generalizes C12 from prefix_length = 0 to any prefix_length
def decrypt_ecb_harder(oracle):
    blocksize = detect_blocksize(oracle)
    prefix_length = detect_prefix_length(oracle)
    known = b''
    # examine each byte of unknown appended text
    for _ in range(len(oracle(b''))-prefix_length):
        # in Z_{blocksize}, [len(prefix)] + [len(known)] = [blocksize - 1] = [-1]
        ptxt = b'X' * (-(prefix_length + len(known)+1) % blocksize)
        # real ciphertext
        ctxt = oracle(ptxt)[:len(ptxt) + prefix_length + len(known) + 1]
        for b in range(256):
            # ciphertext using byte 'b' as last known
            test = oracle(ptxt + known + bytes([b]))[:len(ptxt) + prefix_length + len(known) + 1]
            if ctxt == test:
                known += bytes([b])
                break
    return known