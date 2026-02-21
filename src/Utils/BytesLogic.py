#Basic XOR
def xor_fixed(x: bytes, y:bytes):
    return bytes (xb^yb for xb,yb in zip(x,y))

#Catch-all XOR
def xor(*args: bytes, fixed=False, quiet=True) -> bytes:
    #Ensure there is at least one argument
    assert len(args) > 0

    #Ensure arguments are same length if fixed
    if fixed: assert len(set(map(len, args))) == 1
    
    #Cycle arg and res to desired length. XOR each byte.
    result_size = max(map(len, args))
    res = args[0]
    for arg in args[1:]:
        if not quiet: print(res, arg)
        res = bytes(res[i%len(res)]^arg[i%len(arg)] for i in range(result_size))
    return res

FREQS = {
    'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610,
    'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490, 'm': 0.0202124, 'n': 0.0564513,
    'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357, 'u': 0.0225134,
    'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182}

# Tuned to -0.2, -0.4. These seemed to work as penalties for non-alphabet, non-ASCII characters.
# If we expect lots of special characters, this can be refined.
def score(input_bytes):
    score = 0
    for byte in input_bytes:
        score += FREQS.get(chr(byte).lower(), -0.2)
        if not 32<=byte<=128:
            score -=0.4
    return score

def best_single_xor_key(data: bytes) -> bytes:
    best_key = b''
    max_score = -len(data)
    for key in range(0, 256):
        candidate = xor_single(data, key)
        candidate_score = score(candidate)
        if candidate_score > max_score:
            best_key = key
            max_score = candidate_score
    return bytes([best_key])

def xor_single(x:bytes, y:int):
    return bytes([xb^y for xb in x])

def hamming(x: str, y: str) -> int:
    assert len(x) == len(y)
    res = 0
    for xb, yb in zip(x,y):
        res += (xb^yb).bit_count()
    return res
    
def get_keysize(x):
    best_keysize = -1
    min_distance = float('inf')
    for ks in range(2,40):
        b1,b2,b3,b4 = x[:ks], x[ks:2*ks], x[2*ks:3*ks], x[3*ks:4*ks]
        dist = hamming(b1,b2) + hamming(b1,b3) + \
                hamming(b1,b4) + hamming(b2,b3) + \
                hamming(b2,b4) + hamming(b3,b4)
        dist /= 6*ks
        if dist < min_distance:
            min_distance = dist
            best_keysize = ks
    return best_keysize

def best_repeating_xor_key(ctxt: bytes) -> bytes:
    keysize = get_keysize(ctxt)
    return b"".join(best_single_xor_key(ctxt[i::keysize]) for i in range(keysize))