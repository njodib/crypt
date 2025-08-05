def pkcs7(text, block_size):
    if len(text) % block_size == 0:
        return text
    pad_size = block_size - (len(text) % block_size)
    return b"".join([text, bytes([pad_size]) * pad_size])

def detect_pkcs7(b: bytes):
    n = b[-1]
    #last byte is non-padded and bytes are aligned to block.
    if n > 16 and len(b)%16==0:
        return True
    if n==0 or len(b) < n:
        raise ValueError("INVALID PKCS7 PADDING")
    if not b.endswith(bytes([n]*n)):
        raise ValueError("INVALID PKCS7 PADDING")
    return True

def strip_pkcs7(data: bytes):
    if not detect_pkcs7(data):
        raise ValueError
    return data[:-data[len(data)-1]]