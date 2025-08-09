from Utils.PRNG import Mersenne
from Utils.PRNG import get_state_from_seed

if __name__ == '__main__':
    expectedNumbers = [int(x) for x in open('Data/21.txt', 'r').read().split('\n')[:-1]]
    seed = 5489
    x = get_state_from_seed(seed)
    #x = Mersenne(seed)
    for i, a in enumerate(Mersenne(x, length=999)):    
        print(a)
        if a != expectedNumbers[i]:
            raise Exception(str(i) + ' ' + a + ' != ' + expectedNumbers[i])
    print("SUCCESS")