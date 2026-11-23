from flask import Flask, request, jsonify
import os
import hashlib
import psycopg2

app = Flask(__name__)
DATABASE_URL = os.environ.get("DATABASE_URL", "")

DEFAULT_SERVERS = [
    {"id": "magicnetwork_main", "name": "MagicNetwork", "ip": "168.119.78.155:20217"},
]


def hash_pw(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def get_conn():
    if not DATABASE_URL:
        raise RuntimeError("Hiányzik a DATABASE_URL környezeti változó!")
    return psycopg2.connect(DATABASE_URL, sslmode="require")


def init_db():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_key TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    password_hash TEXT NOT NULL
                )
            """)
        conn.commit()


try:
    init_db()
except Exception:
    pass


@app.get("/servers")
def get_servers():
    return jsonify({"ok": True, "servers": DEFAULT_SERVERS})


@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not (3 <= len(username) <= 16 and username.replace("_", "").isalnum()):
        return jsonify({"ok": False, "message": "A név 3–16 karakter legyen (betű, szám, _)!"}), 400
    if len(password) < 4:
        return jsonify({"ok": False, "message": "A jelszó legalább 4 karakter legyen!"}), 400

    key = username.lower()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM users WHERE user_key = %s", (key,))
            if cur.fetchone():
                return jsonify({"ok": False, "message": "Ez a felhasználónév már foglalt!"}), 409

            cur.execute(
                "INSERT INTO users (user_key, username, password_hash) VALUES (%s, %s, %s)",
                (key, username, hash_pw(password))
            )
        conn.commit()

    return jsonify({"ok": True, "username": username, "message": "Sikeres regisztráció!"})


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    key = username.lower()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT username, password_hash FROM users WHERE user_key = %s", (key,))
            row = cur.fetchone()

    if not row or row[1] != hash_pw(password):
        return jsonify({"ok": False, "message": "Hibás felhasználónév vagy jelszó!"}), 401

    return jsonify({"ok": True, "username": row[0], "message": "Sikeres belépés!"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)