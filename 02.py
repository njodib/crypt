import binascii
from utils import fixed_xor

if __name__ == '__main__':
    IN_A = b'1c0111001f010100061a024b53535009181c'
    IN_B = b'686974207468652062756c6c277320657965'
    OUT = b'746865206b696420646f6e277420706c6179'

    #str bytes
    a = binascii.unhexlify(IN_A)
    b = binascii.unhexlify(IN_B)
    sol = fixed_xor(a, b)

    print("2:", sol)
    assert binascii.hexlify(sol) == OUT