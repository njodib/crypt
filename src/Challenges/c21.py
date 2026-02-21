from Utils.PRNG import MT
import requests

if __name__ == '__main__':
    # List of known results of Mersenne Twister for seed=5489
    URL = "https://oeis.org/A221557/b221557.txt"
    expected = [int(line.split(" ")[1]) for line in requests.get(URL).text.splitlines()]
    real = [r for r in MT(seed = 5489, length=1000)]
    if expected == real: print("SUCCESS")
    else: raise Exception