from base64 import b64decode
from Crypto.Cipher import AES


if __name__ == "__main__":
    with open("Data/07.txt") as input_file:
        ctxt = b64decode(input_file.read())
    cipher = AES.new(b"YELLOW SUBMARINE", AES.MODE_ECB)
    ptxt = cipher.decrypt(ctxt)

    #Test and print
    print(ptxt.decode('utf-8'))
    assert cipher.encrypt(ptxt) == ctxt