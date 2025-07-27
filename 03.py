from utils import single_xor, best_xor_key
import binascii


if __name__ == '__main__':
    IN = b'1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    raw = binascii.unhexlify(IN)

    key = best_xor_key(raw)
    
    print(single_xor(raw, key))
    
    
