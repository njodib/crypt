from Utils.PRNG import Mersenne

if __name__ == '__main__':
    expectedNumbers = [int(x) for x in open('Data/21.txt', 'r').read().split('\n')[:-1]]
    seed = 5489
    x = Mersenne(seed)
    for i, a in enumerate(Mersenne(seed=seed, length=999)):    
        if a != expectedNumbers[i]:
            raise Exception(str(i) + ' ' + a + ' != ' + expectedNumbers[i])
    print("SUCCESS")