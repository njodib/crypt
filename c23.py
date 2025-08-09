from random import randint
from Utils.PRNG import Mersenne, get_state_from_seed

# MT19937 coefficients
(w, n, m, r) = (32, 624, 397, 31)
a = 0x9908B0DF
(u, d) = (11, 0xFFFFFFFF)
(s, b) = (7, 0x9D2C5680)
(t, c) = (15, 0xEFC60000)
l = 18

def distemper(y):
    # turn y into a bitlist
    y = [int(digit) for digit in format(y, '032b')]

    # reverse tempering bitwise operations
    for i in range(l, 32): y[i] ^= y[i - l]
    for i in range(32-t-1, -1, -1): y[i] ^= y[i+t] & int(format(c, '032b')[i])
    for i in range(32-s-1, -1, -1): y[i] ^= y[i+s] & int(format(b, '032b')[i])
    for i in range(u, 32): y[i] ^= y[i - u]
    
    #bitlist to int
    out = 0
    for bit in y:
        out = (out << 1) | bit
    return out

if __name__ == '__main__':
    # Create random number generator
    rng = iter(Mersenne(get_state_from_seed(randint(0, 2**32-1))))

    # distemper 624 random numbers (standard n-cycle)
    # these create a deterministic state vector for rng
    cloned_rng = iter(Mersenne([distemper(next(rng)) for _ in range(n)]))

    # For next 1 million results, assert that the RNGs produce similar values
    for _ in range(10**6):
        assert next(cloned_rng) == next(rng)
    print("SUCCESS")
