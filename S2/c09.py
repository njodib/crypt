from Utils.Padding import pkcs7

if __name__ == "__main__":
    IN = b"YELLOW SUBMARINE"
    BLOCK_SIZE = 20
    OUT = b'YELLOW SUBMARINE\x04\x04\x04\x04'

    padded = pkcs7(IN, BLOCK_SIZE)
    
    print(padded)
    assert padded == OUT