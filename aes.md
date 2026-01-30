## AES

The full algorithm for AES (Advanced Encryption Standard) is specified by the [NIST](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf).

If you are working in command line, it may be easiest to use the suggested [OpenSSL Library](https://docs.openssl.org/3.0/man1/openssl-ciphers/#aes-cipher-suites-from-rfc3268-extending-tls-v10). However, I use the [cryptography library](https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.modes.XTS) in python for my implementation of AES.

## Challenge 7
```python
from base64 import b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def decrypt_aes_ecb(ciphertext, key):
    cipher =  Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    return cipher.decryptor().update(ciphertext)

key = b"YELLOW SUBMARINE"
with open("07.txt") as input_file:
    ciphertext = b64decode(input_file.read())
print(decrypt_aes_ecb(ciphertext, key).decode('utf-8'))
```

## Challenge 8
Notice that 16-byte blocks of plaintext always produce the same 16-byte blocks of ciphertext. If we detect repeated blocks of ciphertext, we can be (almost) certain it is decrypted with ECB

Common 16-character phrases may repeat across long texts. For example: 
```
Plaintext Block:  "As a result of t"...
Ciphertext Block: "C9D9C44365EA33B1C0BEA01447A46EBF"...
```

```python
import numpy as np

with open('08.txt') as fp:
    # Read file
    for line_num,hexstr in enumerate(fp,1):
        # Convert hexstring to bytes
        l = bytes.fromhex(hexstr.strip())
        # Reshape into 16-byte blocks
        array = np.frombuffer(l, dtype="uint8").reshape(-1, 16)
        # Count duplicate blocks
        duplicate_blocks = len(array) - len(np.unique(array, axis=0))
        if duplicate_blocks:
            print(line_num, hexstr)
```

#### Notice!
With the AES cipher, we encrypt plaintext **16 bytes at a time**. So, the repeated plaintext blocks must be aligned correctly for this detection algorithm to work properly.

## Challenge 9
Because of AES's method of 'block' encryption, we can only encrypt plaintext in 16-byte chunks. If our plaintext is not a multiple of 16 bytes, we must pad it accordingly. The current standard is **PKCS #7**, which is standardized in [RFC 5652](https://datatracker.ietf.org/doc/html/rfc5652#section-1). We implement the padding in python.

```python
def pkcs7(txt: bytes, block_size: int = 16) -> bytes:
    pad = block_size - (len(txt) % block_size)
    return txt + bytes([pad] * pad)

padded = pkcs7(b"YELLOW SUBMARINE", 20)
print(padded.decode('utf-8'))
assert padded == b'YELLOW SUBMARINE\x04\x04\x04\x04'
```

## Challenge 10

This challenge implements the CBC mode for AES cipher where ciphertext blocks are propagated through plaintext blocks with the XOR function.

**Equations for encryption and decryption:**
$$
\begin{align*}
    &\text{ECB Encryption: }   && C_j = CIPH_k(P_j) && \text{for }j = 1\dots n\\
    &\text{ECB Decryption: }   && P_j= CIPH_k^{-1}(C_j) && \text{for }j = 1\dots n\\ 
     \\
    &\text{CBC Encryption: }   && C_1 = CIPH_k(P_j\oplus IV) && \\
    & && C_j = CIPH_k(P_j\oplus C_{j-1}) && \text{for }j = 2\dots n\\
    &\text{CBC Decryption: }   && P_1= CIPH_k^{-1}(C_1)\oplus IV && \\
    & && P_j= CIPH_k^{-1}(C_1)\oplus C_{j-1} && \text{for }j = 2\dots n\\
\end{align*}
$$
Further references for ECB mode and CBC mode (among others) can be found in NIST's [Recommendation for Block Cipher Modes of Operation: *Methods and Techniques*](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf).

**Python Implementation:**
```python
from c02 import fixed_xor
from c07 import decrypt_aes_ecb
from c09 import pkcs7
from base64 import b64decode

def aes_cbc_decrypt(ctxt, key, iv = [0]*16):
    ptxt = (fixed_xor(decrypt_aes_ecb(ctxt[0:16], key), iv))
    for i in range(16, len(ctxt)-16, 16):
        ptxt += (fixed_xor(decrypt_aes_ecb(ctxt[i:i+16], key), ctxt[i-16:i]))
    return ptxt

with open("10.txt") as f:
    ctxt = pkcs7(b64decode(f.read()),16)
ptxt = aes_cbc_decrypt(ctxt, b"YELLOW SUBMARINE", [0]*16)
print(ptxt.decode())
```

**Output:**
```
I'm back and I'm ringin' the bell 
A rockin' on the mike while the fly girls yell 
In ecstasy in the back of me 
Well that's my DJ Deshay cuttin' all them Z's 
Hittin' hard and the girlies goin' crazy 
Vanilla's on the mike, man I'm not lazy. 

I'm lettin' my drug kick in 
It controls my mouth and I begin 
To just let it flow, let my concepts go 
My posse's to the side yellin', Go Vanilla Go! 

Smooth 'cause that's the way I will be 
And if you don't give a damn, then 
Why you starin' at me 
So get off 'cause I control the stage 
There's no dissin' allowed 
I'm in my own phase 
The girlies sa y they love me and that is ok 
And I can dance better than any kid n' play 

Stage 2 -- Yea the one ya' wanna listen to 
It's off my head so let the beat play through 
So I can funk it up and make it sound good 
1-2-3 Yo -- Knock on some wood 
For good luck, I like my rhymes atrocious 
Supercalafragilisticexpialidocious 
I'm an effect and that you can bet 
I can take a fly girl and make her wet. 

I'm like Samson -- Samson to Delilah 
There's no denyin', You can try to hang 
But you'll keep tryin' to get my style 
Over and over, practice makes perfect 
But not if you're a loafer. 

You'll get nowhere, no place, no time, no girls 
Soon -- Oh my God, homebody, you probably eat 
Spaghetti with a spoon! Come on and say it! 

VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino 
Intoxicating so you stagger like a wino 
So punks stop trying and girl stop cryin' 
Vanilla Ice is sellin' and you people are buyin' 
'Cause why the freaks are jockin' like Crazy Glue 
Movin' and groovin' trying to sing along 
All through the ghetto groovin' this here song 
Now you're amazed by the VIP posse. 

Steppin' so hard like a German Nazi 
Startled by the bases hittin' ground 
There's no trippin' on mine, I'm just gettin' down 
Sparkamatic, I'm hangin' tight like a fanatic 
You trapped me once and I thought that 
You might have it 
So step down and lend me your ear 
'89 in my time! You, '90 is my year. 

You're weakenin' fast, YO! and I can tell it 
Your body's gettin' hot, so, so I can smell it 
So don't be mad and don't be sad 
'Cause the lyrics belong to ICE, You can call me Dad 
You're pitchin' a fit, so step back and endure 
Let the witch doctor, Ice, do the dance to cure 
So come up close and don't be square 
You wanna battle me -- Anytime, anywhere 

You thought that I was weak, Boy, you're dead wrong 
So come on, everybody and sing this song 

Say -- Play that funky music Say, go white boy, go white boy go 
play that funky music Go white boy, go white boy, go 
Lay down and boogie and play that funky music till you die. 

Play that funky music Come on, Come on, let me hear 
Play that funky music white boy you say it, say it 
Play that funky music A little louder now 
Play that funky music, white boy Come on, Come on, Come on 
Play that funky music 
```


## Challenge 11
```python
from random import randint, randbytes
import numpy as np
from c07 import aes_encrypt_ecb
from c09 import pkcs7
from c10 import aes_encrypt_cbc

def rand_aes_encrypt(ptxt):
    key = randbytes(16)
    ptxt = randbytes(randint(5,10)) + ptxt + randbytes(randint(5,10))
    ptxt = pkcs7(ptxt, 16)
    if randint(0,1) == 0:
        return aes_encrypt_cbc(ptxt, key, randbytes(16)), "CBC"
    else:
        return aes_encrypt_ecb(ptxt, key), "ECB"

def aes_detect_mode(ctxt):
    array = np.frombuffer(ctxt, dtype="uint8").reshape(-1, 16)
    duplicate_blocks = len(array) - len(np.unique(array, axis=0))
    return "ECB" if 0<duplicate_blocks else "CBC"

for i in range(1,11):
    ptxt = b"sixteencharblock"*4
    ctxt, actual_mode = rand_aes_encrypt(ptxt)
    detected_mode = aes_detect_mode(ctxt)
    assert actual_mode == detected_mode
print("All tests passed :)")
```

**Output**
```
All tests passed :)
```