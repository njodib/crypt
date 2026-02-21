from Utils.Padding import PKCS7
if __name__ == '__main__':
    assert PKCS7().detect_padding(b'ICE ICE BABY\x04\x04\x04\x04') == True
    assert PKCS7().detect_padding(b'ICE ICE BABY\x05\x05\x05\x05') == False
    assert PKCS7().detect_padding(b'ICE ICE BABY\x01\x02\x03\x04') == False
    assert PKCS7().detect_padding(b'ICE ICE BABY') == False
