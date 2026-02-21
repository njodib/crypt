from Utils.Padding import PKCS7
from Utils.Cipher import detect_mode, detect_blocksize
from Utils.Decrypt import decrypt_ecb_harder
from Utils.Oracles import C14_Oracle

if __name__ == '__main__':
    # Build Oracle
    oracle = C14_Oracle()

    # Determine blocksize of cipher
    blocksize = detect_blocksize(oracle)
    print("BLOCKSIZE:", blocksize, "\n")
    assert blocksize == 16

    # Determine encryption mode of cipher
    mode = detect_mode(oracle)
    print("MODE:", mode, "\n")
    assert mode == "ECB"

    # Examine appended ciphertext
    print("Interestingly, empty inputs always return the same ciphertext.")
    print("CIPHERTEXT FROM EMPTY INPUT:", oracle(b"").hex(), "\n")

    # Decrypt appended ciphertext
    ptxt_secret = decrypt_ecb_harder(oracle)
    print("DECRYPTED MESSAGE:")
    print(PKCS7(blocksize).unpad(ptxt_secret).decode().rstrip())