from flask import Flask, request, jsonify, render_template
import json, base64, hmac, hashlib, os, uuid, time

app = Flask(__name__)

SECRET_KEY = "s3cret"  # Weak, guessable secret
FLAG_PATH = os.path.join(os.path.dirname(__file__), 'flag.txt')

def init_lab():
    if os.path.exists(FLAG_PATH):
        os.remove(FLAG_PATH)
    flag = f"KX{{{uuid.uuid4().hex[:16]}}}"
    with open(FLAG_PATH, "w") as f:
        f.write(flag)

def read_flag():
    if os.path.exists(FLAG_PATH):
        with open(FLAG_PATH, "r") as f:
            return f.read().strip()
    return "KX{ERROR_NO_FLAG}"

def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64url_decode(s):
    s += '=' * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def create_jwt(payload, secret=SECRET_KEY):
    header = {"alg": "HS256", "typ": "JWT"}
    h = b64url_encode(json.dumps(header).encode())
    p = b64url_encode(json.dumps(payload).encode())
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    s = b64url_encode(sig)
    return f"{h}.{p}.{s}"

def verify_jwt(token):
    """
    VULNERABILITY: Accepts 'none' algorithm — skips signature verification entirely.
    Also uses a weak secret key that's guessable.
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None, "Invalid token format"

        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))

        alg = header.get("alg", "HS256")

        # VULNERABILITY: 'none' algorithm accepted
        if alg.lower() == "none":
            return payload, None

        # Verify signature with weak secret
        expected_sig = hmac.new(SECRET_KEY.encode(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
        actual_sig = b64url_decode(parts[2])

        if hmac.compare_digest(expected_sig, actual_sig):
            return payload, None
        else:
            return None, "Invalid signature"

    except Exception as e:
        return None, f"Token error: {str(e)}"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    username = data.get("username")
    password = data.get("password")

    # Simple hardcoded auth
    valid_users = {
        "viewer": {"password": "viewer123", "role": "viewer"},
    }

    user = valid_users.get(username)
    if not user or user["password"] != password:
        return jsonify({"error": "Invalid credentials"}), 401

    payload = {
        "sub": username,
        "role": user["role"],
        "iat": int(time.time()),
    }

    token = create_jwt(payload)
    return jsonify({
        "token": token,
        "message": f"Logged in as {username} (role: {user['role']})"
    })

@app.route("/api/profile")
def profile():
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        return jsonify({"error": "Authorization header required (Bearer <token>)"}), 401

    token = auth.split(" ", 1)[1]
    payload, err = verify_jwt(token)

    if err:
        return jsonify({"error": err}), 401

    return jsonify({
        "user": payload.get("sub"),
        "role": payload.get("role"),
        "message": f"Welcome, {payload.get('sub')}. Your role is: {payload.get('role')}"
    })

@app.route("/api/admin")
def admin():
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        return jsonify({"error": "Authorization header required (Bearer <token>)"}), 401

    token = auth.split(" ", 1)[1]
    payload, err = verify_jwt(token)

    if err:
        return jsonify({"error": err}), 401

    if payload.get("role") != "admin":
        return jsonify({"error": "Admin role required", "your_role": payload.get("role")}), 403

    return jsonify({
        "message": "Admin access granted",
        "flag": read_flag()
    })

if __name__ == "__main__":
    init_lab()
    app.run(host="0.0.0.0", port=5000, debug=False)
