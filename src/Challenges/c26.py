from Utils.BytesLogic import xor
from Utils.Oracles import C26_Oracle

def prefix_length(oracle) -> int:
    c1 = oracle.encode(b'XXXX')
    c2 = oracle.encode(b'OOOO')
    for i in range(len(c1)):
        if c1[i] != c2[i]:
            return i

if __name__ == '__main__':
    # setup oracle
    oracle = C26_Oracle()
    p = prefix_length(oracle)
    
    # target is illegal input
    target = b';admin=true;'
    t = len(target)

    # XOR legal input with illegal input for new ctxt
    legal = b'A'*t  #legal input with target length
    mask = xor(target, legal) #mask changes ctxt of input to ctxt for target
    ctxt = oracle.encode(legal)
    ctxt = ctxt[:p] + xor(ctxt[p:p+t], mask) + ctxt[p+t:]
    
    # Test
    assert oracle.parse(ctxt)
    print("SUCCESS")