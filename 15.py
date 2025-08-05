from Utils.Padding import detect_pkcs7

if __name__ == "__main__":
    valid = [
        b"ICE ICE BABY\x04\x04\x04\x04",
        b"LOADSIXTEENBYTES"
    ]

    invalid = [
        b"ICE ICE BABY\x05\x05\x05\x05"
        b"ICE ICE BABY\x01\x02\x03\x04"
    ]

    for x in valid:
        assert detect_pkcs7(x) == True

    for x in invalid:
        try: detect_pkcs7(x)
        except: pass
        else: raise Exception("ACCEPTED INVALID PADDING")

    print("SUCCESS")
