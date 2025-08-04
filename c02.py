def xor_bytes(x:bytes,y:bytes) -> bytes:
    assert len(x)==len(y)
    return bytes([xb^yb for (xb,yb) in zip(x,y)])

if __name__ == '__main__':
    #Save as raw bytes
    A = bytes.fromhex('1c0111001f010100061a024b53535009181c')
    B = bytes.fromhex('686974207468652062756c6c277320657965')
    C = bytes.fromhex('746865206b696420646f6e277420706c6179')

    #Test and print
    assert xor_bytes(A, B) == C
    print(C.decode('utf-8'))

