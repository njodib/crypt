
from random import randbytes
from Utils.PublicKeyGen import DiffieHellman
from Utils.AES import AES_CBC
from Utils.Hash import SHA1

alice = DiffieHellman()
bob = DiffieHellman(alice.p, alice.g)

# MITM
# Alice -> Bob
A = alice.public_key

# Bob -> Alice
B = bob.public_key

# MITM sends both public keys with p, so Alice and Bob will compute the shared secret as 0.
# Thus, MITM has knowledge of the 'shared seceret' and can decrypt all messages.
# This all happens in separate contexts for Alice and Bob, so they don't know that the MITM is in the middle.
A = alice.p
B = bob.p

# Alice -> Bob
a_ctxt = alice.send(b"Hello Bob!", B)
print("Alice -> Bob:", a_ctxt.hex())

# Bob -> Alice
b_ctxt = bob.send(b"Hello Alice!", A)
print("Bob -> Alice:", b_ctxt.hex())

# MITM decrypting both messages with the shared secret of 0
a_ptxt = alice.receive(a_ctxt, B)
b_ptxt = bob.receive(b_ctxt, A)
print("Alice decrypted:", a_ptxt.decode())
print("Bob decrypted:", b_ptxt.decode())
