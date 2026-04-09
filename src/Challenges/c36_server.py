from flask import Flask, request, jsonify
from random import randint
from hashlib import sha256 as SHA2
from Utils.Hash import HMAC
import base64

app = Flask(__name__)

def modexp(b, e, m):
    # https://en.wikipedia.org/wiki/Modular_exponentiation)
    # right --> left binary
    res = 1
    b = b % m
    while e > 0:
        if e % 2 == 1:
            res = (res * b) % m
        e = e // 2
        b = (b * b) % m
    return res

N = 37
g = 2
k = 3
I = "goop@goop.com"
P = "hunter2"
K = None
salt = randint(0, 2**32)

@app.route('/', methods=['POST'])
def login():
    global K
    
    print(f"Salt: {salt}") #random int salt
    xH = SHA2(salt.to_bytes(4, 'big') + P.encode()).digest()
    print(f"xH: {xH}") #32 bit hashed salt and password
    x = int.from_bytes(xH, 'big')
    print(f"x: {x}") #integer x
    v = modexp(g, x, N)
    print(f"v: {v}") #verifier v


    if request.method == 'POST':
        # REQUEST 1 TEST        
        if 'test' in request.get_json():
            post_data = request.get_json()
            print(post_data)

            if post_data:
                return jsonify({"status": "success", "received": post_data}), 200
            else:
                return jsonify({"status": "error", "message": "No data received"}), 400

        # REQUEST 2 SEND I, A
        if 'I' in request.get_json() and 'A' in request.get_json():
            post_data = request.get_json()
            I = post_data.get('I')
            A = post_data.get('A')

            b = randint(1, N - 1)
            B = (k * v + modexp(g, b, N)) % N
            print(f"B: {B}")

            # GENERATE u
            uH = SHA2(str(A).encode() + str(B).encode()).digest()
            print(f"uH: {uH}") #hashed A and B
            u = int.from_bytes(uH, 'big')
            print(f"u: {u}") #integer u

            # GENERATE S
            S = modexp(A * modexp(v, u, N), b, N)
            print(f"S: {S}") #shared secret S   

            # GENERATE K
            K = SHA2(S.to_bytes((S.bit_length() + 7) // 8, 'big')).digest()
            print(f"K: {K}") #session key K
            return jsonify(salt=salt, B=B)
        
        if 'hm' in request.get_json():
            post_data = request.get_json()
            hm = base64.b64decode(post_data.get('hm').encode('utf-8'))
            print(f"Received HMAC: {hm}")
            expected_hm = HMAC.sha256(K, salt.to_bytes(4, 'big'))
            print(f"Expected HMAC: {expected_hm}")
            if hm == expected_hm:
                return jsonify({"status": "success", "message": "HMAC is correct!"}), 200
            else:
                return jsonify({"status": "error", "message": "HMAC is incorrect!"}), 400


def main():
    app.run()


if __name__ == '__main__':
    main()

