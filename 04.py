from utils import single_xor, error, best_xor_key
import binascii

min_error = float('inf')
message = None

with open('Data/04.txt') as fp:
    for line in fp:
        l = binascii.unhexlify(line.strip())
        key = best_xor_key(l)
        candidate = single_xor(l, key)
        if error(candidate) < min_error:
            min_error = error(candidate)
            message = candidate
    print(message)