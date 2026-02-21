from time import time, sleep
from random import randint
from random import Random
from Utils.PRNG import MT

def crack_MT_timeseed(x:int):
    # ASSUME: x is the first rng value
    # ASSUME: rng system created <2000 seconds ago

    t = int(time())
    for i in range(2000):
        if x==next(MT(seed=t-i)):
            return t-i
    raise Exception("Not found :(")

if __name__ == "__main__":
    # default seed is unix time
    rng = MT()
    x = next(rng)
    print("Your random number is:", x)

    # simulate code running // passing time
    print("Running code...")
    sleep(4)

    # crack seed
    seed = crack_MT_timeseed(x)
    print("\nSuccess!\nSeed uncovered:", seed)

    # check
    rng_cracked = MT(seed)
    next(rng_cracked)
    print("\nExpected random number:", next(rng_cracked))
    print("Actual random number:", next(rng))