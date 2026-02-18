from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3, os, uuid

app = Flask(__name__)
app.secret_key = os.urandom(24)

DB_PATH = os.path.join(os.path.dirname(__file__), 'app.db')
FLAG_PATH = os.path.join(os.path.dirname(__file__), 'flag.txt')

def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    if os.path.exists(FLAG_PATH):
        os.remove(FLAG_PATH)

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('''
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        email TEXT,
        department TEXT,
        role TEXT DEFAULT 'employee'
    )
    ''')

    c.execute("INSERT INTO users (username, password, email, department, role) VALUES ('jdoe', 'Welcome2024!', 'jdoe@corp.local', 'Security', 'employee')")

    conn.commit()
    conn.close()
    generate_flag()

def generate_flag():
    flag_value = f"KX{{{uuid.uuid4().hex[:16]}}}"
    with open(FLAG_PATH, "w") as f:
        f.write(flag_value)

def read_flag():
    if os.path.exists(FLAG_PATH):
        with open(FLAG_PATH, "r") as f:
            return f.read().strip()
    return "KX{ERROR_NO_FLAG}"

@app.route("/")
def index():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        result = c.execute(query).fetchone()

        if result:
            session["user_id"] = result[0]
            session["username"] = result[1]
            session["email"] = result[3]
            session["department"] = result[4]
            session["role"] = result[5]
            session["logged_in"] = True
            return redirect("/dashboard")
        else:
            return render_template("login.html", error="Invalid credentials")
    except Exception as e:
        return render_template("login.html", error=f"System Error: {e}")
    finally:
        conn.close()

@app.route("/dashboard")
def dashboard():
    if not session.get("logged_in"):
        return redirect("/")

    flag = None
    if session.get("role") == "admin":
        flag = read_flag()

    return render_template("dashboard.html",
                         username=session.get("username"),
                         email=session.get("email"),
                         department=session.get("department"),
                         role=session.get("role"),
                         flag=flag)

@app.route("/profile")
def profile():
    if not session.get("logged_in"):
        return redirect("/")

    return render_template("profile.html",
                         username=session.get("username"),
                         email=session.get("email"),
                         department=session.get("department"),
                         role=session.get("role"))

@app.route("/update-profile", methods=["POST"])
def update_profile():
    """VULNERABILITY: Accepts role parameter from form — hidden field can be tampered with"""
    if not session.get("logged_in"):
        return redirect("/")

    email = request.form.get("email")
    department = request.form.get("department")
    role = request.form.get("role", session.get("role"))

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE users SET email = ?, department = ?, role = ? WHERE id = ?",
              (email, department, role, session.get("user_id")))
    conn.commit()
    conn.close()

    session["email"] = email
    session["department"] = department
    session["role"] = role

    return redirect("/dashboard")

@app.route("/admin")
def admin():
    if not session.get("logged_in"):
        return redirect("/")

    if session.get("role") != "admin":
        return render_template("error.html", message="Access Denied: Admin privileges required")

    return render_template("admin.html", flag=read_flag())

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
