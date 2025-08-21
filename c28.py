from random import randbytes
from Utils.Hash import SHA1_MAC

if __name__ == "__main__":
    msg = b"abc" #from NIST std.
    for i in range(5):
        key = randbytes(16)
        print("Test", i, "->", SHA1_MAC(msg, key).hex())
    print("SUCCESS")