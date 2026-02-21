from Utils.Padding import PKCS7

if __name__ == "__main__":
    # Verify PKCS7 padding works as expected
    ptxt = b"YELLOW SUBMARINE"
    padding = PKCS7(20)
    padded_ptxt = padding.pad(ptxt)
    assert padding.unpad(padded_ptxt) == ptxt