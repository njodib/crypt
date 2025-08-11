BLOCK_SIZE = 16

def blockify(data: bytes, bs:int=16):
    return [data[i:i+bs] for i in range(0,len(data),bs)]

if __name__ == "__main__":
    result = [] #Store lines with duplicate blocks in result
    with open('Data/08.txt') as fp:
        for idx, line in enumerate(fp):
            ctxt = bytes.fromhex(line)
            blocks = blockify(ctxt) 
            if len(set(blocks)) < len(blocks):
                result += [(idx, line)]
    
    for (idx, ctxt) in result:
        print("LINE:", idx)
        print("CTXT:", ctxt)
        print()


        

