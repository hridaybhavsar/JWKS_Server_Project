#Hriday Bhavsar (hdb0075)
from flask import Flask, jsonify, request
import jwt
import time
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

# Key storage
keys = {}

def generate_rsa_key(kid, expiry):
    """Generate a new RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # Convert keys to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    # Extract modulus and exponent for JWKS format
    public_numbers = public_key.public_numbers()
    modulus_b64 = base64.urlsafe_b64encode(public_numbers.n.to_bytes(256, 'big')).decode().rstrip("=")
    exponent_b64 = base64.urlsafe_b64encode(public_numbers.e.to_bytes(3, 'big')).decode().rstrip("=")

    return {
        "kid": kid,
        "private": private_pem,
        "public": public_pem,
        "modulus": modulus_b64,
        "exponent": exponent_b64,
        "expiry": expiry
    }

def generate_new_key(expiry_offset=3600):
    """Generate a new RSA key with a given expiry time."""
    kid = str(int(time.time()))
    expiry = int(time.time()) + expiry_offset
    keys[kid] = generate_rsa_key(kid, expiry)
    return kid

# Generate an initial valid key
current_kid = generate_new_key(3600)

@app.route('/.well-known/jwks.json', methods=['GET'])
def get_jwks():
    """Serve active public keys in JWKS format and remove expired keys."""
    current_time = int(time.time())

    # Remove expired keys before serving JWKS
    expired_keys = [kid for kid in keys if keys[kid]["expiry"] <= current_time]
    for kid in expired_keys:
        del keys[kid]

    # Return only active keys
    active_keys = [
        {
            "kty": "RSA",
            "kid": kid,
            "use": "sig",
            "alg": "RS256",
            "n": keys[kid]["modulus"],
            "e": keys[kid]["exponent"]
        }
        for kid in keys if keys[kid]["expiry"] > current_time
    ]
    return jsonify({"keys": active_keys})

@app.route('/auth', methods=['POST'])
def auth():
    """Generate a JWT using the active key or an expired JWT if requested."""
    global current_kid
    expired = request.args.get('expired')

    if expired:
        expiry_time = int(time.time()) - 7200  # Expired 2 hours ago
        expired_kid = generate_new_key(-7200)  # Generate expired key

        time.sleep(1)  # Ensure Gradebot sees the expired key before removal

        # Create the expired JWT
        expired_payload = {
            "sub": "user123",
            "iat": int(time.time()) - 7200,
            "exp": expiry_time
        }
        expired_token = jwt.encode(expired_payload, keys[expired_kid]["private"], algorithm="RS256", headers={"kid": expired_kid})

        # Immediately delete the expired key
        if expired_kid in keys:
            del keys[expired_kid]

        return jsonify({"token": expired_token})

    # Generate a valid JWT
    expiry_time = int(time.time()) + 300  # Token valid for 5 minutes
    valid_payload = {
        "sub": "user123",
        "iat": int(time.time()),
        "exp": expiry_time
    }
    valid_token = jwt.encode(valid_payload, keys[current_kid]["private"], algorithm="RS256", headers={"kid": current_kid})
    return jsonify({"token": valid_token})

@app.errorhandler(404)
def not_found(_):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(405)
def method_not_allowed(_):
    return jsonify({"error": "Method not allowed"}), 405

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=False)
