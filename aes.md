

## Challenge 7

**AES**

The full algorithm for AES (Advanced Encryption Standard) is specified by the [NIST](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf).

If you are working in command line, it may be easiest to use the suggested [OpenSSL Library](https://docs.openssl.org/3.0/man1/openssl-ciphers/#aes-cipher-suites-from-rfc3268-extending-tls-v10). However, I use the [pycryptodome library](https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html) for a python implementation of AES.

For these next challenges, I build out an AES class inside my Utils folder.

**AES ECB Implementation**
```python
class AES_ECB:
    def __init__(self, key):
        self.key = key

    def enc(self, ptxt: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.encrypt(ptxt, AES.block_size)

    def dec(self, ctxt: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.decrypt(ctxt)
```

For this challenge:
1. Make a request to the [txt](https://www.cryptopals.com/static/challenge-data/7.txt) file
2. Decode the base64 text into ciphertext bytes
3. Decrypt the ciphertext bytes into plaintext
4. Test decryption by re-encrypting the plaintext. If it's valid, it should return the same ciphertext

```python
from base64 import b64decode
from Utils.AES import AES_ECB
import requests

if __name__ == "__main__":
    # 1. Save ciphertext
    URL = "https://www.cryptopals.com/static/challenge-data/7.txt"
    ctxt_encoded = requests.get(URL).text
    
    # 2. Transform the base64 ciphertext string into bytes
    ctxt = b64decode(ctxt_encoded)

    # 3. Decrypt ciphertext with AES ECB using the known key
    KEY = b"YELLOW SUBMARINE"
    cipher = AES_ECB(KEY)
    ptxt = cipher.dec(ctxt)
    print(ptxt.decode('utf-8'))

    # 4. Test: re-encrypt plaintext and compare to ciphertext
    assert cipher.enc(ptxt) == ctxt
    print("SUCCESS")
```

## Challenge 8
Notice that 16-byte blocks of plaintext always produce the same 16-byte blocks of ciphertext.

```
Plaintext Block:  "As a result of t"...
Ciphertext Block: "C9D9C44365EA33B1C0BEA01447A46EBF"...
```

For long English text, we expect repeated phrases to eventually align in the 16-byte buffer.

```python
import requests

def blockify(data: bytes, bs: int=16):
    return [data[i:i+bs] for i in range(0,len(data),bs)]

if __name__ == "__main__":
    # 1. Save ciphertext
    URL = "https://www.cryptopals.com/static/challenge-data/8.txt"
    ctxt_str = requests.get(URL).text
    
    # 2. Iterate through lines, splitting into 16 byte blocks
    for i, ctxt_line in enumerate(ctxt_str.splitlines(),1):
        ctxt = bytes.fromhex(ctxt_line)
        blocks = blockify(ctxt,16)
        
        # 3. Return line containing duplicate blocks.
        if len(set(blocks)) < len(blocks):
            print("Found ECB encryption in line", i)
            print("Ciphertext:", ctxt_line)
```

Notice our **blockify** helper function. This comes in handy pretty frequently for block ciphers :)

## Challenge 9
Because of AES's method of 'block' encryption, we can only encrypt plaintext in 16-byte chunks. If our plaintext is not a multiple of 16 bytes, we must pad it accordingly. The current standard is **PKCS #7**, which is standardized in [RFC 5652](https://datatracker.ietf.org/doc/html/rfc5652#section-1).

PKCS#7 padding adds N bytes, ensuring that the total length is a multiple of block_size. The value of each added byte is equal to N.

**Note:** If the length of the original data is an integer multiple of the block size B, then an extra block of bytes with value B is added. This is necessary so the deciphering algorithm can determine with certainty whether the last byte of the last block is a pad byte indicating the number of padding bytes added or part of the plaintext message. [[wikipedia]](https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7)

We implement PKCS#7 padding

```python
def pkcs7(txt: bytes, block_size: int = 16) -> bytes:
    pad = block_size - (len(txt) % block_size)
    return txt + bytes([pad] * pad)
```

And complete the challenge

```python
from Utils.Padding import pkcs7

if __name__ == "__main__":
    # 1. Return padded data
    padded = pkcs7(b"YELLOW SUBMARINE", 20)
    print(padded)

    # 2. Test
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

**Notice:** The XOR prevents the problem of repeated 16-byte blocks.

Further references for ECB mode and CBC mode (among others) can be found in NIST's [Recommendation for Block Cipher Modes of Operation: *Methods and Techniques*](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf).

**Implement CBC Mode:**
```python
class AES_CBC:
    def __init__(self, key, iv=[0]*16):
        self.cipher = AES_ECB(key, AES.MODE_ECB)
        self.iv = iv
    
    def aes_cbc_decrypt(self, ctxt):
        # Break ciphertext into blocks
        blocks = blockify(ctxt,16)
        # P_1 = D(C_1) XOR IV
        ptxt = xor(self.cipher.dec(blocks[0]), self.iv)
        # P_i = D(C_i) XOR C_(i-1) for i>1
        for i in range(1, len(blocks)):
            ptxt += xor(self.cipher.dec(blocks[i]), blocks[i-1])
        return ptxt
    
    def aes_cbc_encrypt(self, ptxt):
        # Break plaintext into blocks
        blocks = blockify(ptxt,16)
        # C_1 = E(P_1 XOR IV)
        ctxt = self.cipher.enc(xor(blocks[0],self.iv))
        # C_i = E(P_i XOR C_(i-1)) for i>1
        for i in range(1, len(blocks)):
            ctxt += self.cipher.enc(xor(blocks[i], ctxt[(i-1)*16:i*16]))
        return ctxt
```

And complete the challenge
```python
from base64 import b64decode
from Utils.AES import AES_CBC
import requests

if __name__ == "__main__":
    # 1. Save ciphertext
    URL = "https://www.cryptopals.com/static/challenge-data/10.txt"
    ctxt_str = requests.get(URL).text
    ctxt = b64decode(ctxt_str)

    # 2. Decrypt ciphertext with AES CBC using the known key and IV
    KEY = b"YELLOW SUBMARINE"
    IV = [0]*16
    cipher = AES_CBC(KEY, IV)
    print(cipher.dec(ctxt).decode('utf-8'))
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
Here, I begin a separate file for oracles.

If everything is set up correctly from the previous challenges this should be pretty straightforward.

```python
from random import randint, randbytes, getrandbits
from Utils.AES import AES_ECB, AES_CBC
from Utils.Padding import pkcs7

class C11_Oracle:
    def __init__(self):
        if getrandbits(1):
            self.mode = "ECB"
            self.cipher = AES_ECB(randbytes(16))
        else:
            self.mode = "CBC"
            iv = randbytes(16)
            self.cipher = AES_CBC(randbytes(16), randbytes(16))

    def __call__(self, ptxt: bytes) -> bytes:
        # Prepend and append random bytes
        ptxt = randbytes(randint(5,10)) + ptxt + randbytes(randint(5,10))
        # Pad plaintext
        ptxt = pkcs7(ptxt, 16)
        # Encrypt randomly using ECB or CBC
        return self.cipher.enc(ptxt)
    
    # For testing only. Oracle should never actually reveal its mode.
    def get_mode(self):
        return self.mode
```

Although we don't know the alignment for the 16-byte buffer, if we pass in a string of repeated characters, we can eventually expect repeated blocks in ECB mode. Notice how this repeats logic from Challenge 8 of finding repeated blocks to "detect ECB encryption". 

```python
from c08 import blockify
from Utils.Oracles import C11_Oracle

def break_C11_oracle(oracle):
    # String of identical bytes to trigger ECB detection
    ptxt = b'X'*64
    ctxt = oracle(ptxt)

    # Break ciphertext into blocks and check for duplicates
    blocks = blockify(ctxt,16)
    if len(set(blocks)) < len(blocks): return "ECB"
    else: return "CBC"

if __name__ == '__main__':
    print("\nTesting C11 Oracle...")
    oracle = C11_Oracle()
    
    ptxt = b"This is some plaintext to be encrypted."
    print("Plaintext:", ptxt.decode('utf-8'))
    print("Ciphertext:", oracle(ptxt).hex())

    print("\nDetected encryption mode:", break_C11_oracle(oracle))
    print("Actual encryption mode:", oracle.get_mode())
    
    print("\nRunning tests...")
    for _ in range(5):
        detected = break_C11_oracle(oracle)
        actual = oracle.get_mode()
        assert detected == actual
    print("SUCCESS")
```

## Challenge 12

First, let's build an encryption oracle similar to the one we made for Challenge 11. We should always **append** the unknown string, but never return it directly.

```python
class C12_Oracle:
    def __init__(self):
        self.cipher = AES_ECB(randbytes(16))
        self.unknown = b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
            "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
            "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
            "YnkK"
        )

    def __call__(self, ptxt:bytes) -> bytes:
        ptxt += self.unknown
        ptxt = pkcs7(ptxt, 16)
        return self.cipher.enc(ptxt)
```

We know the blocksize is 16. But how would we determine this exactly? All ciphertexts are returned in blocks. So we can make the plaintext input larger and larger until the ciphertext returns an additional block. The difference in the two sizes is the block's length.

BUT we cannot pass in plaintext bytes whose length is not a multiple of blocksize. We can either:
    - Add padding functionality to encrypt/decrypt functions
    - Check for exceptions until we get a valid length. This length is a multiple of blocksize.
I implement the first one because cookies can be variable size and I want to match a standard email input. But either one is fine.

```python
# Determine block size of encryption oracle
def detect_blocksize(enc) -> int:
    # Get length of ciphertext for empty input
    len1 = len(enc(pkcs7(b'')))
    # Increment input length until ciphertext length increases
    for i in count(0):
        len2 = len(enc(b"X"*i))
        # When ciphertext length increases, we've crossed a block boundary
        if len2 != len1: 
            return len2 - len1
```

But 

To verify the mode, we can simply reuse the logic from Challenge 11's *detect_mode* function. We pass in our encryption oracle and assert the mode is ECB.

The first unknown byte of appended text should be at the end of a block. If we know the previous 15 bytes, we can iterate through possibilities for the last byte and find a matching ciphertext block.

```python
# Imports
from Utils.Padding import strip_pkcs7
from itertools import count

# Get next byte of unknown string by brute-forcing all possibilities
def get_next_byte(enc, bs, ptxt=b""):
    # Align ciphertext so next unknown byte is at block boundary
    pad = b'X' * (((bs-1)- len(ptxt)) % bs)
    assert len(pad + ptxt) % bs == bs-1
    ctxt = enc(pad)

    # Iterate through possible last-byte values. Check for equality.
    for i in range(256):
        test = enc(pad + ptxt + bytes([i]))
        if test[:len(pad)+len(ptxt)+1] == ctxt[:len(pad)+len(ptxt)+1]:
            return bytes([i])
    return b''

# Decrypt unknown string appended by oracle, byte-by-byte.
def crack_ECB(enc, bs=16):
    ptxt = b''
    for _ in range(len(enc(b''))):
        ptxt += get_next_byte(enc, bs, ptxt)
    return strip_pkcs7(ptxt)
```

We should expect the output to have standard padding. Let's create a small helper function to strip this PKCS#7 padding.

```python
def strip_pkcs7(data: bytes):
    return data[:-data[len(data)-1]]
```

We complete the challenge

```python
# Imports
from c11 import detect_mode
from Utils.Oracles import C12_Oracle

if __name__ == "__main__":
    # Build encryption oracle
    enc = C12_Oracle()
    print("Testing C12 Oracle...")
    ptxt = b"HELLO WORLD"
    print("\nPlaintext:", ptxt)
    print("Ciphertext:", enc(ptxt).hex())

    # Examine ciphertext for empty plaintext
    print("\nInterestingly, empty plaintext always returns the same ciphertext.")
    print("Ciphertext:", enc(b"").hex())

    # Discover blocksize of cipher
    bs = detect_blocksize(enc)
    print("\nDetected block size:", bs)
    assert bs == 16

    # Ensure oracle is using ECB
    mode = detect_mode(enc)
    print("Detected mode:", mode)
    assert mode == "ECB"

    # Decrypt unknown string
    print("\nDECRYPTED CIPHERTEXT:")
    ptxt = crack_ECB(enc, bs)
    print(ptxt.decode('utf-8'))
```
## Challenge 13
Python implementation:
```python
from random import randbytes
from Utils.Padding import pkcs7, strip_pkcs7
from Utils.AES import AES_ECB
from c08 import blockify
from c12 import detect_blocksize

def detect_msg_length(oracle) -> int:
    block_size = detect_blocksize(oracle)
    base_len = len(oracle(b''))
    for i in range(block_size+1):
        tmp_len = len(oracle(b'A'*i))
        if tmp_len > base_len:
            return base_len - i

def get_injection_block(oracle):
    #find injection block by determining the first block which changes when 1 byte is added
    a = blockify(oracle(b""))
    b = blockify(oracle(b"A"))
    inj = 0
    while a[inj] == b[inj]: inj += 1
    return inj

def get_prefix_size(oracle):
    block_size = detect_blocksize(oracle)
    inj = get_injection_block(oracle)

    #When injection block is filled with padding, it stops changing
    inj_pad = 0
    while True:
        inj_short = blockify(oracle(b"A"*inj_pad))[inj]
        inj_long = blockify(oracle(b"A"*(inj_pad+1)))[inj]
        if inj_short == inj_long:
            break
        inj_pad += 1
    prefix_length = (inj * block_size) + (block_size - inj_pad)
    return prefix_length

def get_postfix_size(oracle):
    bs = detect_blocksize(oracle)
    pref = get_prefix_size(oracle)
    msg = detect_msg_length(oracle)
    end_padding = bs - (msg % bs)
    post = len(oracle(b"")) - pref - end_padding
    return post

class Profile:
    def __init__(self):
        self.key = randbytes(16)
        self.user = {}
        self.blocksize = 16
        self.cipher = AES_ECB(self.key)
    
    @staticmethod
    def kv_parse(cookie:bytes) -> dict:
        s = cookie.decode('utf-8')
        return dict(pair.split('=') for pair in s.split('&'))

    @staticmethod
    def profile_for(email: bytes) -> bytes:
        if b'&' in email or b'=' in email: raise ValueError("Invalid")
        email = email.replace(b'&', b'').replace(b'=', b'')
        return b'email='+email+b'&uid=10&role=user'

    #Email -> Update profile -> Return ciphertext
    def enc(self, email: str) -> bytes:
        profile = self.profile_for(email)
        padded_profile = pkcs7(profile, self.blocksize)
        ctxt = self.cipher.enc(padded_profile)
        return ctxt

        #return str(pkcs7(AES_ECB(self.key), self.blocksize).enc(profile))

    #Encrypted profile
    def dec(self, ctxt: bytes):
        ptxt = strip_pkcs7(AES_ECB(self.key).dec(ctxt))
        return self.kv_parse(ptxt)

# U could just inspect the cookie too.
# But this code generalizes to any cookie
if __name__ == "__main__":
    # Define the encryption oracle
    prof = Profile()
    oracle = prof.enc

    # Encryption information from oracle
    bs = detect_blocksize(oracle)
    msg_len = detect_msg_length(oracle)
    inj = get_injection_block(oracle)
    pre = get_prefix_size(oracle)
    post = get_postfix_size(oracle)

    # Fill the injection block with Xs
    # Encrypt padded 'admin' block
    fake_email_len = ((inj+1)*16)-pre
    fake_email = (b'X'*fake_email_len) + pkcs7(b'admin', bs)
    admin_ctxt = oracle(fake_email)[(inj+1)*bs:(inj+2)*bs]

    # Align 'user' to last block.
    # Replace this with the padded 'admin' block
    admin_email_len = bs - ((len(prof.profile_for(b''))-len('user'))%bs)
    admin_email = b"X"*admin_email_len #Any 13 char email
    ctxt = oracle(admin_email)[:-bs] + admin_ctxt

    # Test and print
    dec = prof.dec(ctxt)
    print(dec)
    assert dec['role'] == 'admin'
```

 