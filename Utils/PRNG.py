from time import time


#  MT19937
# https://en.wikipedia.org/wiki/Mersenne_Twister
# https://dl.acm.org/doi/10.1145/272991.272995

# COEFFICIENTS
# word size (bits), degree of recurrence, middle word offset, separation point(lower bitmask)
(w, n, m, r) = (32, 624, 397, 31) 
# coefficients of rational normal twist matrix
a = 0x9908B0DF
# tempering: bitmask + associated bit shift
(s, b) = (7, 0x9D2C5680)
(t, c) = (15, 0xEFC60000)
(u, d) = (11, 0xFFFFFFFF)
l = 18
# magic number ^_^
f = 1812433253
# masks
lower_mask = (1<<r)-1
upper_mask = ((1<<w)-1) - ((1<<r)-1)
w_mask = (1 << w) - 1


def temper(y):
    y ^= (y>>u) & d
    y ^= (y<<s) & b
    y ^= (y<<t) & c
    y ^= (y>>l)
    return y

def distemper(y):
    # turn y into a bitlist
    y = [int(digit) for digit in format(y, '032b')]

    # reverse tempering bitwise operations
    for i in range(l, 32): y[i] ^= y[i - l]
    for i in range(32-t-1, -1, -1): y[i] ^= y[i+t] & int(format(c, '032b')[i])
    for i in range(32-s-1, -1, -1): y[i] ^= y[i+s] & int(format(b, '032b')[i])
    for i in range(u, 32): y[i] ^= y[i - u]
    
    #bitlist to int
    res = 0
    for bit in y: res = (res << 1) | bit
    return res



class MT:    
    def __init__(self, seed:int=int(time()), state: list=None, length: int = None):
        if state: self.x = state
        else: self.x = get_state_from_seed(seed)
        self.index = 0
        self.length = length

    def __iter__(self):
        idx = 0
        while True:
            idx += 1
            if self.length is not None and self.length < idx:
                break
            if self.index == n:
                self.twist()
            
            y = temper(self.x[self.index])

            self.index += 1
            yield d&y

    def twist(self):
        for i in range(n):
            # rational normal matrix multiplication
            y = (self.x[i] & upper_mask) + (self.x[(i+1)%n] & lower_mask)
            self.x[i] = (self.x[(i+m)%n]) ^ (y>>1)
            if y%2 != 0: self.x[i] ^= a
        self.index = 0
    
    def temper(self, y):
        y ^= (y>>u) & d
        y ^= (y<<s) & b
        y ^= (y<<t) & c
        y ^= (y>>l)
        return y

    def __next__(self):
        if self.index == n: self.twist()
        y = temper(self.x[self.index])
        self.index += 1
        return y

def get_state_from_seed(seed):
    x = [seed]
    for i in range(1, n+1):
        x += [d & (f * (x[i-1] ^ (x[i-1] >> (w-2))) + i)]
    return x

