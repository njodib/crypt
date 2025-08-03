import base64
import binascii

if __name__ == '__main__':
    IN = b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    OUT = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    
    str_bytes = binascii.unhexlify(IN)
    print(str_bytes)
    
    str_base64 = base64.b64encode(str_bytes)
    assert str_base64 == OUT
