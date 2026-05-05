from flask import Flask, jsonify, request
import jwt
import datetime
import sqlite3
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

DB_FILE = "totally_not_my_privateKeys.db"


# --------------------------
# Database Setup
# --------------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
    """)

    conn.commit()
    conn.close()


# --------------------------
# Key Generation + Storage
# --------------------------
def generate_and_store_key(expired=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    if expired:
        exp = int((datetime.datetime.utcnow() - datetime.timedelta(hours=1)).timestamp())
    else:
        exp = int((datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp())

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # ✅ Parameterized query (prevents SQL injection)
    cursor.execute(
        "INSERT INTO keys (key, exp) VALUES (?, ?)",
        (private_pem, exp)
    )

    conn.commit()
    conn.close()


# --------------------------
# Initialize DB + Keys
# --------------------------
init_db()

# Ensure at least one valid + one expired key
generate_and_store_key(expired=False)
generate_and_store_key(expired=True)


# --------------------------
# JWKS Endpoint
# --------------------------
@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    now = int(datetime.datetime.utcnow().timestamp())

    cursor.execute(
        "SELECT kid, key FROM keys WHERE exp > ?",
        (now,)
    )

    rows = cursor.fetchall()
    conn.close()

    keys = []

    for kid, private_pem in rows:
        private_key = serialization.load_pem_private_key(private_pem, password=None)
        public_key = private_key.public_key()

        numbers = public_key.public_numbers()

        keys.append({
            "kid": str(kid),
            "kty": "RSA",
            "use": "sig",
            "n": hex(numbers.n)[2:],
            "e": hex(numbers.e)[2:]
        })

    return jsonify({"keys": keys})


# --------------------------
# Auth Endpoint
# --------------------------
@app.route("/auth", methods=["POST"])
def auth():
    use_expired = request.args.get("expired") == "true"

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    now = int(datetime.datetime.utcnow().timestamp())

    if use_expired:
        cursor.execute(
            "SELECT kid, key FROM keys WHERE exp < ? LIMIT 1",
            (now,)
        )
    else:
        cursor.execute(
            "SELECT kid, key FROM keys WHERE exp > ? LIMIT 1",
            (now,)
        )

    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "No suitable key found"}), 500

    kid, private_pem = row

    payload = {
        "user": "userABC",
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }

    token = jwt.encode(
        payload,
        private_pem,
        algorithm="RS256",
        headers={"kid": str(kid)}
    )

    return jsonify({"token": token})


if __name__ == "__main__":
    app.run(port=8080)