import time
import hmac
import hashlib
from flask import Flask, request, Response

app = Flask(__name__)
SECRET_KEY = b"YELLOW_SUBMARINE"  # In a real app, this would be secret

def insecure_compare(actual, provided):
    if len(actual) != len(provided):
        return False
    
    for b1, b2 in zip(actual, provided):
        if b1 != b2:
            return False
        # The artificial leak: 50ms per matching byte
        time.sleep(0.005)
    return True

@app.route('/test')
def test_signature():
    file = request.args.get('file', '')
    signature = request.args.get('signature', '')
    
    # Calculate what the real HMAC should be
    real_hmac = hmac.new(SECRET_KEY, file.encode(), hashlib.sha1).hexdigest()
    
    if insecure_compare(real_hmac, signature):
        return Response("Success!", status=200)
    else:
        return Response("Invalid Signature", status=500)

if __name__ == '__main__':
    app.run(port=9000)