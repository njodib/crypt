def xor(x: bytes, y:bytes):
    return bytes (xb^yb for xb,yb in zip(x,y))

