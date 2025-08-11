from Utils.PRNG import MT

if __name__ == '__main__':
    with open('Data/21.txt', 'r') as file:
        expected = [int(line.rstrip()) for line in file]

        real = [r for r in MT(seed = 5489, length=1000)]
        if expected == real: print("SUCCESS")
        else: raise Exception