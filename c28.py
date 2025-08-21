from random import randbytes
from Utils.Hash import SHA1

def secret_prefix_MAC(msg:bytes) -> bytes:
    return SHA1(randbytes(16)+msg)

if __name__ == "__main__":
    msg = b"abc"
    for _ in range(5):
        print(secret_prefix_MAC(msg).hex())
    print("SUCCESS")