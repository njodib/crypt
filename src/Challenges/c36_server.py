from flask import Flask, request, jsonify, render_template_string
from random import randint
from hashlib import sha256 as SHA2
from Utils.Hash import HMAC
import base64

app = Flask(__name__)

@app.route('/')
def index():
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>SRP Login</title>
        <style>
            body { font-family: sans-serif; margin: 50px; background: #f4f4f4; }
            .login-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); width: 300px; }
            input { width: 100%; padding: 8px; margin: 10px 0; box-sizing: border-box; }
            button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; cursor: pointer; }
        </style>
    </head>
    <body>
        <div class="login-card">
            <h3>SRP Authentication</h3>
            <label>Username (I):</label>
            <input type="text" id="username_input">
            
            <label>Password (P):</label>
            <input type="password" id="password_input">
            
            <button onclick="performLogin()">Login</button>
            <p id="status"></p>
        </div>

        <script>
            async function performLogin() {
                // 1. Get the value from the 'I' textbox
                const usernameValue = document.getElementById('username_input').value;
                const status = document.getElementById('status');
                
                // 2. Client-side math: Generate public key 'A' 
                // (Using a random int for this example to match your N=37)
                const a = Math.floor(Math.random() * 30) + 1;
                const A = Math.pow(2, a) % 37; 

                status.innerText = "Sending credentials...";

                // 3. Send the value of 'I' and 'A' to the Flask backend
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        "I": usernameValue, 
                        "A": A
                    })
                });

                const data = await response.json();
                console.log("Server Response:", data);
                status.innerText = "Server received I: " + usernameValue;
            }
        </script>
    </body>
    </html>
    """
    return render_template_string(html_content)

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
P = {"goop@goop.com": "hunter2"}
K = None
salt = randint(0, 2**32)

@app.route('/', methods=['POST'])
def login():
    global K
    
    

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

            
            print(f"Salt: {salt}") #random int salt
            xH = SHA2(salt.to_bytes(4, 'big') + P[I].encode()).digest()
            print(f"xH: {xH}") #32 bit hashed salt and password
            x = int.from_bytes(xH, 'big')
            print(f"x: {x}") #integer x
            v = modexp(g, x, N)
            print(f"v: {v}") #verifier v



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

