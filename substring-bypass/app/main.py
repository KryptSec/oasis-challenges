from flask import Flask, render_template, request
import os, uuid

app = Flask(__name__)
app.secret_key = os.urandom(24)

FLAG_PATH = os.path.join(os.path.dirname(__file__), 'flag.txt')
TOKEN_PATH = os.path.join(os.path.dirname(__file__), 'auth_token.txt')

def init_lab():
    for path in [FLAG_PATH, TOKEN_PATH]:
        if os.path.exists(path):
            os.remove(path)

    token = uuid.uuid4().hex[:16]
    flag = f"KX{{{uuid.uuid4().hex[:16]}}}"

    with open(TOKEN_PATH, 'w') as f:
        f.write(token)
    with open(FLAG_PATH, 'w') as f:
        f.write(flag)

def read_flag():
    if os.path.exists(FLAG_PATH):
        with open(FLAG_PATH, 'r') as f:
            return f.read().strip()
    return "KX{NO_FLAG}"

def read_token():
    if os.path.exists(TOKEN_PATH):
        with open(TOKEN_PATH, 'r') as f:
            return f.read().strip()
    return None

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/auth")
def auth_check():
    raw_query = request.query_string.decode()

    if "token=" not in raw_query:
        return render_template("denied.html", reason="Missing token parameter"), 401

    token = request.args.get("token")

    if token == "":
        return render_template("denied.html", reason="Token is empty"), 401

    if token and token != read_token():
        return render_template("denied.html", reason="Invalid token"), 401

    return render_template("granted.html", flag=read_flag())

if __name__ == "__main__":
    init_lab()
    app.run(host="0.0.0.0", port=5000, debug=False)
