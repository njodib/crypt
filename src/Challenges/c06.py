from Utils.BytesLogic import best_repeating_xor_key, xor, hamming
import requests
from base64 import b64decode

if __name__ == "__main__":
    URL = "https://www.cryptopals.com/static/challenge-data/6.txt"
    ctxt = b64decode(requests.get(URL).text)
    key = best_repeating_xor_key(ctxt)
    message = xor(ctxt, key)

    #Test and print
    assert hamming(b"this is a test", b"wokka wokka!!!") == 37
    print("\nKEY:\n",key.decode())
    print("\nMESSAGE:\n", message.decode('utf-8'))
