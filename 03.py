from utils import fixed_xor
import binascii

frequencies = {'a': 0.0855, 'b': 0.0160, 'c': 0.0316, 'd': 0.0387, 'e': 0.1209,
               'f': 0.0218, 'g': 0.0209, 'h': 0.0496, 'i': 0.0732, 'j': 0.0022,
               'k': 0.0081, 'l': 0.0420, 'm': 0.0253, 'n': 0.0717, 'o': 0.0747,
               'p': 0.0206, 'q': 0.0010, 'r': 0.0633, 's': 0.0673, 't': 0.0894,
               'u': 0.0268, 'v': 0.0106, 'w': 0.0182, 'x': 0.0019, 'y': 0.0172,
               'z': 0.0011}

def error(candidate: bytes) -> float:
    l = len(candidate)
    score = 0
    for char, expected_freq in frequencies.items():
        freq = candidate.count(ord(char)) / l
        err = abs(freq - expected_freq)
        score += err
    return score
    

if __name__ == '__main__':
    IN = b'1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    raw = binascii.unhexlify(IN)

    #minimize error
    best_key = -1
    min_error = float('inf')
    for key in range(0,256):
        candidate = fixed_xor(raw, [key]*256)
        candidate_error = error(candidate)
        if candidate_error < min_error:
            best_key = key
            min_error = candidate_error
    
    #solution
    print("3:",fixed_xor(raw, [best_key]*256))
    
    
