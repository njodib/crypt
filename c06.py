from base64 import b64decode
from c03 import best_xor_key
from c05 import repeating_xor

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

if __name__ == "__main__":
    with open("Data/06.txt") as input_file:
        data = b64decode(input_file.read())
    keysize = get_keysize(data)
    key = bytes([best_xor_key(data[i::keysize]) for i in range(keysize)])
    message = repeating_xor(data, key)

    #Test and print
    print("\nKEY:\n",key.decode())
    print("\nMESSAGE:\n", message.decode('utf-8'))
    assert hamming(b"this is a test", b"wokka wokka!!!") == 37
    assert repeating_xor(message, key) == data
