from Utils.BytesLogic import best_single_xor_key, xor

if __name__ == '__main__':
    IN = bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    key = best_single_xor_key(IN)
    print(xor(IN, key).decode('utf-8'))