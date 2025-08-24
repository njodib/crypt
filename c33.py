from random import randint

# (b**e)%m
def modexp(b, e, m):
    # https://en.wikipedia.org/wiki/Modular_exponentiation)
    # right --> left binary
    res = 1
    while e > 0:
        b, e, res = (
            b * b % m,
            e >> 2,
            b * res % m if e % 2 else res
        )

    return res

# -------- SMALL NUMBERS ---------

# public parameters
p = 37
g = 4

a = randint(1,p) # Alice secret key
b = randint(1,p) # Bob secret key

A = modexp(g,a,p) #Alice public key
B = modexp(g,b,p) # Bob public key

s1 = modexp(B,a,p) # Alice secret
s2 = modexp(A,b,p) # Bob secret

assert s1 == s2 #ensure similarity

# -------- BIG NUMBERS -----------

# public parameters
p = int('ffffffffffffffffc90fdaa22168c234c4c6628b80d'
        'c1cd129024e088a67cc74020bbea63b139b22514a08'
        '798e3404ddef9519b3cd3a431b302b0a6df25f14374'
        'fe1356d6d51c245e485b576625e7ec6f44c42e9a637'
        'ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f241'
        '17c4b1fe649286651ece45b3dc2007cb8a163bf0598'
        'da48361c55d39a69163fa8fd24cf5f83655d23dca3a'
        'd961c62f356208552bb9ed529077096966d670c354e'
        '4abc9804f1746c08ca237327ffffffffffffffff ', 16)
g = 2

# secret keys
a = randint(1,p)
b = randint(1,p)

# public keys
A = modexp(g,a,p)
B = modexp(g,b,p)

# secrets
s1 = modexp(B,a,p)
s2 = modexp(A,b,p)

assert s1 == s2
print("Success")