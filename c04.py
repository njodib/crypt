from c03 import best_xor_key, error

if __name__ == "__main__":
    min_error = float('inf')
    message = None

    with open('Data/04.txt') as fp:
        for line in fp:
            l = bytes.fromhex(line)
            key = best_xor_key(l)
            candidate = bytes([lb^key for lb in l])
            if error(candidate) < min_error:
                min_error = error(candidate)
                message = candidate

    print(message.decode('utf-8'))