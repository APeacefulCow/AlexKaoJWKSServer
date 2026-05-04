from flask import Flask, jsonify, request
import jwt
import datetime
import uuid
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

# In-memory key store
KEYS = []


def generate_key(expired=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    exp = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    if expired:
        exp = datetime.datetime.utcnow() - datetime.timedelta(hours=1)

    kid = str(uuid.uuid4())

    KEYS.append({
        "kid": kid,
        "private": private_key,
        "public": public_key,
        "exp": exp
    })


# Create initial keys
generate_key(expired=False)
generate_key(expired=True)


# JWKS endpoint
@app.route("/jwks", methods=["GET"])
def jwks():
    keys = []

    for k in KEYS:
        if k["exp"] > datetime.datetime.utcnow():
            pub = serialization.load_pem_public_key(k["public"])
            numbers = pub.public_numbers()

            keys.append({
                "kid": k["kid"],
                "kty": "RSA",
                "use": "sig",
                "n": hex(numbers.n)[2:],
                "e": hex(numbers.e)[2:]
            })

    return jsonify({"keys": keys})


# Auth endpoint
@app.route("/auth", methods=["POST"])
def auth():
    use_expired = request.args.get("expired") == "true"

    key = None

    for k in KEYS:
        if use_expired and k["exp"] < datetime.datetime.utcnow():
            key = k
            break
        if not use_expired and k["exp"] > datetime.datetime.utcnow():
            key = k
            break

    payload = {
        "user": "test_user",
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }

    token = jwt.encode(
        payload,
        key["private"],
        algorithm="RS256",
        headers={"kid": key["kid"]}
    )

    return jsonify({"token": token})


if __name__ == "__main__":
    app.run(port=8080)