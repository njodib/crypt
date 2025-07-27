from utils import pkcs7_pad

txt = "YELLOW SUBMARINE"
block_size = 20
padded = pkcs7_pad(b"YELLOW SUBMARINE", 20)
print(padded)
assert padded == b'YELLOW SUBMARINE\x04\x04\x04\x04'
