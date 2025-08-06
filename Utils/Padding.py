def pkcs7(text, block_size):
    if len(text) % block_size == 0:
        return text
    pad_size = block_size - (len(text) % block_size)
    return b"".join([text, bytes([pad_size]) * pad_size])

def detect_pkcs7(data):
    pkcs7 = True
    last_byte_padding = data[-1]
    if(last_byte_padding < 1 or last_byte_padding > 16):
      pkcs7 = False
    else:
      for i in range(0,last_byte_padding):
        if(last_byte_padding != data[-1-i]):
          pkcs7 = False
    return pkcs7

def strip_pkcs7(data: bytes):
    if not detect_pkcs7(data):
        raise ValueError
    if len(data)%16==0: return data
    return data[:-data[len(data)-1]]