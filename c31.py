from time import sleep, time
from Utils.Hash import HMAC

class Oracle():
    def __init__(self):
        #we know it's 20 bytes from std. HMAC length :)
        self.secret = HMAC.sha1(b"abc", b"hello")
        print("Actual: ",self.secret.hex())

    def insecure_compare(self,a:bytes):
        b=self.secret
        #then system checks equality byte-by-byte
        for ax,bx in zip(a,b):
            if ax==bx: sleep(0.05) #50 ms (seems to be the magic number idk)
            else: return False
        return True
    
def next_byte(partial:bytes, compare, l):
    zeroes = b"\x00"*(l-len(partial)-1)
    best_byte, best_delta = b'\x00', 0
    for x in range(256):
        y = x.to_bytes()
        t0 = time()
        compare(partial + y + zeroes)
        t1 = time()
        delta = t1-t0
        
        #deltas += [delta]
        if best_delta < delta:
            best_delta = delta
            best_byte = y
    return best_byte

def crack(length, compare):
    res = b""
    l=length
    for _ in range(l):
        res += next_byte(res, compare,l)
        print("Partial:",res.hex())
    return res

def crack_hmac(compare):
    return crack(20,compare)

def main():
    orc = Oracle()    
    res = crack_hmac(orc.insecure_compare)
    print("Found:  ", res.hex())

    if orc.insecure_compare(res): print("SUCCESS")
    else: print("FAILURE")

if __name__ == '__main__':
    main()