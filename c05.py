from itertools import cycle

def repeating_xor(a: bytes, key) -> bytes:
    return bytes([x^y for (x,y) in zip(a,cycle(key))])

if __name__ == "__main__":
    IN = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    KEY = b'ICE'
    OUT = bytes.fromhex("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")

    #First pass XOR
    encrypted = repeating_xor(IN, KEY)
    assert encrypted == OUT

    #Second pass XOR
    decrypted = repeating_xor(encrypted, KEY)
    assert decrypted == IN
    print(decrypted.decode('utf-8'))
