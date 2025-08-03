def pkcs7_pad_valid(b: bytes):
    n = b[-1]
    if n == 0 or len(b) < n or not b.endswith(bytes([n]*n)):
        raise ValueError("INVALID PKCS7 PADDING")
    return True

tests = [
    b"ICE ICE BABY\x04\x04\x04\x04",\
    b"ICE ICE BABY\x05\x05\x05\x05",\
    b"ICE ICE BABY\x01\x02\x03\x04"\
]
assert pkcs7_pad_valid(tests[0]) == True
try:
    pkcs7_pad_valid(tests[1])
except:
    pass
else:
    raise Exception("ACCEPTED INVALID PADDING")
try:
    pkcs7_pad_valid(tests[2])
except:
    pass
else:
    raise Exception("ACCEPTED INVALID PADDING")
print("SUCCESS")