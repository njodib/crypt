from Utils.Padding import pkcs7

txt = "YELLOW SUBMARINE"
block_size = 20
padded = pkcs7(b"YELLOW SUBMARINE", 20)
print(padded.decode('utf-8'))
assert padded == b'YELLOW SUBMARINE\x04\x04\x04\x04'
