from base64 import b64decode
from Utils.AES import AES_CBC

if __name__ == "__main__":
    KEY = b"YELLOW SUBMARINE"
    IV = [0]*16

    with open("Data/10.txt") as input_file:
        ctxt = b64decode(input_file.read())

    cipher = AES_CBC(KEY, IV)
    print(cipher.dec(ctxt).decode('utf-8'))