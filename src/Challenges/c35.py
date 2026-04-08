#Implement DH with negotiated groups, and break with malicious "g" parameters

# imports
from Utils.PublicKeyGen import DiffieHellman

# Alice and Bob are using DiffieHellman with the same p and g, but a MITM is in the middle and can modify the g parameter to be 1, p, or p-1. This causes the shared secret to be 1, 0, or 1 (respectively), which the MITM can easily compute and use to decrypt all messages.
p=37 # or any other prime i guess

g = 1
alice = DiffieHellman(p,g)
bob = DiffieHellman(p,g)
# s = 1^ab = 1
assert alice.s(bob.public_key) == bob.s(alice.public_key) == 1 

g = p
alice = DiffieHellman(p,g)
bob = DiffieHellman(p,g)
# s = 0^ab = 0
assert alice.s(bob.public_key) == bob.s(alice.public_key) == 0

g = p-1
alice = DiffieHellman(p,g)
bob = DiffieHellman(p,g)
# s = (-1)^ab = 1 or p-1 in Z_p
assert alice.s(bob.public_key) == bob.s(alice.public_key) == 1 or alice.s(bob.public_key) == bob.s(alice.public_key) == alice.p - 1