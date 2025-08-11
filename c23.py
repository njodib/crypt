from Utils.PRNG import MT

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
    res = 0
    for bit in y: res = (res << 1) | bit
    return res

def clone_rng(rng):
    # distemper standard cycle of 624 random numbers
    # creates a deterministic state vector for random number generator :)
    return iter(MT(state=[distemper(next(rng)) for _ in range(n)]))

if __name__ == '__main__':
    # Create random number generator
    rng = MT()

    # Clone RNG from its output
    clone = clone_rng(rng)

    # Ensure clone is valid for 1 mil 'random' numbers
    for _ in range(10**6): assert next(clone) == next(rng)
    print("SUCCESS")