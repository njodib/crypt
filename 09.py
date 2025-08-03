def pad(text, block_size):
    if len(text) % block_size == 0:
        return text
    pad_size = block_size - (len(text) % block_size)
    return b"".join([text, bytes([pad_size]) * pad_size])
print(pad(b"YELLOW SUBMARINE", 20))