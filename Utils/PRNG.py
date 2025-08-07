class Mersenne:
    #https://en.wikipedia.org/wiki/Mersenne_Twister
    # MT19937
    #word size (bits), degree of recurrence, middle word offset, separation point(lower bitmask)
    (w, n, m, r) = (32, 624, 397, 31) 
    #coefficients of rational normal twist matrix
    a = 0x9908B0DF
    #tempering: bitmask + associated bit shift
    (s, b) = (7, 0x9D2C5680)
    (t, c) = (15, 0xEFC60000)
    (u, d) = (11, 0xFFFFFFFF)
    l = 18
    #magic number ^_^
    f = 1812433253
    #masks
    lower_mask = (1<<r)-1
    upper_mask = ((1<<w)-1) - ((1<<r)-1)
    w_mask = (1 << w) - 1

    def __init__(self, seed: int = 5489, length: int = None):
        self.x = self.seed_x(seed)
        self.index = self.n
        self.length = length
    
    def __iter__(self):
        idx = 0
        while True:
            idx += 1
            if self.length is not None and self.length < idx:
                break
            if self.index == self.n:
                self.twist()
            
            #tempering transform
            y = self.x[self.index]
            y ^= (y>>self.u) & self.d
            y ^= (y<<self.s) & self.b
            y ^= (y<<self.t) & self.c
            y ^= (y>>self.l)

            self.index += 1
            yield self.d&y

    def seed_x(cls, seed:int) -> list[int]:
        #initialize series x
        x = [seed]
        for i in range(1, cls.n+1):
            x += [cls.d & (cls.f * (x[i-1] ^ (x[i-1] >> (cls.w-2))) + i)]
        return x

    def twist(self):
        for i in range(self.n):
            # rational normal matrix multiplication
            y = (self.x[i] & self.upper_mask) + (self.x[(i+1)%self.n] & self.lower_mask)
            self.x[i] = (self.x[(i+self.m)%self.n]) ^ (y>>1)
            if y%2 != 0: self.x[i] ^= self.a
        self.index = 0 #twisting resets index to 0