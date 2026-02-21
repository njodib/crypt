class PKCS7():
    def __init__(self, blocksize=16):
        self.blocksize = blocksize
    
    def detect_padding(self, ptxt):
        pad = ptxt[-ptxt[-1]:]
        return all(pad[b] == len(pad) for b in range(0, len(pad)))

    def unpad(self, ptxt):
        if self.detect_padding(ptxt): return ptxt[:-ptxt[-1]]
        else: return ptxt#raise Exception("Bad padding!")
    
    def pad(self, ptxt):
        if len(ptxt) != self.blocksize:
            b = self.blocksize - len(ptxt) % self.blocksize
            ptxt += bytes([b] * b)
        return ptxt