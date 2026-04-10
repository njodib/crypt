from flask import Flask, request, jsonify, render_template
from random import randint
from hashlib import sha256 as SHA2
import base64

app = Flask(__name__)

# Config (Keep these small for your N=37 test, but usually these are 2048-bit)
N, g, k = 37, 2, 3
# In a real app, 'v' and 'salt' are stored in a database after registration
I_db = "goop@goop.com"
P_db = "hunter2"
salt = 12345 

def hash_str(data):
    return SHA2(str(data).encode()).hexdigest()

def get_v(p_str, s_int):
    x = int(hash_str(f"{salt}{P_db}"), 16)
    return pow(g, x, N)



v = get_v(P_db, salt)
server_sessions = {} # Simple memory store for A, b, and K

@app.route('/')
def index():
    return render_template('index.html', server_status="Server is running...")

@app.route('/step1', methods=['POST'])
def step1():
    data = request.json
    client_I, A = data['I'], int(data['A'])
    
    if client_I != I_db: return jsonify({"error": "User not found"}), 404

    # Generate server ephemeral
    b = randint(1, N - 1)
    B = (k * v + pow(g, b, N)) % N
    
    # Calculate shared secret S & session key K
    u = int(SHA2(f"{A}{B}".encode()).hexdigest(), 16)
    S = pow(A * pow(v, u, N), b, N)
    K = hash_str(S)
    
    # Store K indexed by A (simple session simulation)
    server_sessions[str(A)] = {"K": K, "salt": salt}
    print(f"Server calculated S: {S}")
    print(f"Server generated B: {B}")
    
    return jsonify({"salt": salt, "B": B})

@app.route('/step2', methods=['POST'])
def step2():
    data = request.json
    A_str, client_hm = str(data['A']), base64.b64decode(data['hm'])
    
    session = server_sessions.get(A_str)
    print(f"Server received proof: {client_hm}")
    print(f"Server session data: {session}")
    if not session: return jsonify({"error": "Session expired"}), 400
    
    # Verify proof: In reality, use a proper HMAC-SHA256
    # For simplicity, we just check if SHA2(K + salt) matches
    expected = SHA2(f"{session['K']}{session['salt']}".encode()).hexdigest()
    print(f"Server expected proof: {expected}")
    if client_hm.decode() == expected:
        return jsonify({"status": "Authenticated!"})
    return jsonify({"status": "Access Denied"}), 401

if __name__ == '__main__':
    app.run(port=5000)