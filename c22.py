from time import time
from random import randint
from Utils.PRNG import Mersenne

if __name__ == "__main__":
    t = int(time())
    print("TIME:", t)
    t += randint(40,1000)
    x = next(Mersenne(t))

    t +=  randint(40,1000)
    for i in range(2000):
        if x==next(Mersenne(t-i)):
            print("SEED:", t-i)