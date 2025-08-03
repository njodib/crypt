def pkcs7(text, block_size):
    if len(text) % block_size == 0:
        return text
    pad_size = block_size - (len(text) % block_size)
    return b"".join([text, bytes([pad_size]) * pad_size])

def detect_pkcs7(data: bytes):
    #expected padding
    pad = data[-data[-1]:]
    return all(pad[b]==len(pad) for b in range(0, len(pad)))

def strip_pkcs7(data: bytes):
    if not detect_pkcs7(data):
        raise ValueError
    return data[:-data[len(data)-1]]