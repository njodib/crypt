from time import time
from random import randint
from Utils.PRNG import Mersenne, get_state_from_seed

if __name__ == "__main__":

    t = int(time())
    t += randint(40,1000)
    
    x = next(Mersenne(get_state_from_seed(t)))

    t +=  randint(40,1000)
    for i in range(2000):
        if x==next(Mersenne(get_state_from_seed(t-i))):
            print("SEED:", t-i)