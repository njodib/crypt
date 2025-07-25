def fixed_xor(a: bytes, b: bytes) -> bytes:
    return bytes (i^j for i,j in zip(a,b))