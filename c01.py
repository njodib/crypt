from base64 import b64decode

if __name__ == '__main__':
    #Save as raw bytes
    IN = bytes.fromhex('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
    OUT = b64decode('SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t')

    #Test and print
    assert IN == OUT
    print(IN.decode('utf-8'))