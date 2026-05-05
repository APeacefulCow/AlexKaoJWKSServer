from flask import Flask, jsonify, request
import jwt
import datetime
import sqlite3
import os
import uuid
import time
from collections import deque

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from argon2 import PasswordHasher

app = Flask(__name__)

DB_FILE = "totally_not_my_privateKeys.db"

# =========================
# AES SETUP
# =========================
AES_KEY = os.environ.get("NOT_MY_KEY", "defaultinsecurekey123")[:32].encode()

def encrypt_key(data: bytes) -> bytes:
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(AES_KEY), modes.ECB())
    encryptor = cipher.encryptor()

    return encryptor.update(padded) + encryptor.finalize()

def decrypt_key(enc_data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(AES_KEY), modes.ECB())
    decryptor = cipher.decryptor()

    padded = decryptor.update(enc_data) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# =========================
# PASSWORD HASHING
# =========================
ph = PasswordHasher()


# =========================
# RATE LIMITING
# =========================
request_times = deque()
RATE_LIMIT = 10
WINDOW = 1  # seconds


# =========================
# DATABASE INIT
# =========================
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

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS auth_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    conn.commit()
    conn.close()


# =========================
# KEY GENERATION
# =========================
def generate_and_store_key(expired=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    encrypted = encrypt_key(private_pem)

    if expired:
        exp = int((datetime.datetime.utcnow() - datetime.timedelta(hours=1)).timestamp())
    else:
        exp = int((datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp())

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO keys (key, exp) VALUES (?, ?)",
        (encrypted, exp)
    )

    conn.commit()
    conn.close()


# =========================
# INIT
# =========================
init_db()

# Ensure at least one valid and expired key
generate_and_store_key(expired=False)
generate_and_store_key(expired=True)


# =========================
# REGISTER ENDPOINT
# =========================
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    username = data.get("username")
    email = data.get("email")

    if not username:
        return jsonify({"error": "Missing username"}), 400

    password = str(uuid.uuid4())
    password_hash = ph.hash(password)

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
            (username, password_hash, email)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "User exists"}), 400

    conn.close()

    return jsonify({"password": password}), 201


# =========================
# JWKS ENDPOINT
# =========================
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

    for kid, enc_key in rows:
        private_pem = decrypt_key(enc_key)

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


# =========================
# AUTH ENDPOINT
# =========================
@app.route("/auth", methods=["POST"])
def auth():
    # -------- Rate Limiting --------
    now_time = time.time()

    while request_times and now_time - request_times[0] > WINDOW:
        request_times.popleft()

    if len(request_times) >= RATE_LIMIT:
        return jsonify({"error": "Too many requests"}), 429

    request_times.append(now_time)

    # -------- Determine key --------
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

    if not row:
        conn.close()
        return jsonify({"error": "No key found"}), 500

    kid, enc_key = row
    private_pem = decrypt_key(enc_key)

    # -------- User lookup --------
    username = "userABC"

    cursor.execute(
        "SELECT id FROM users WHERE username = ?",
        (username,)
    )

    user = cursor.fetchone()
    user_id = user[0] if user else None

    # -------- Log request --------
    cursor.execute(
        "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)",
        (request.remote_addr, user_id)
    )

    conn.commit()
    conn.close()

    # -------- Create JWT --------
    payload = {
        "user": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }

    token = jwt.encode(
        payload,
        private_pem,
        algorithm="RS256",
        headers={"kid": str(kid)}
    )

    return jsonify({"token": token})


# =========================
# RUN SERVER
# =========================
if __name__ == "__main__":
    app.run(port=8080)