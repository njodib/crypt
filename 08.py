import binascii
import numpy as np

with open('08.txt') as fp:
    for line in fp:
        l = binascii.unhexlify(line.strip())
        array = np.frombuffer(l, dtype="uint8").reshape(-1, 16)
        duplicate_blocks = len(array) - len(np.unique(array, axis=0))
        if 0 < duplicate_blocks:
            print(line)
        

