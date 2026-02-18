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

    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT DEFAULT 'user')")
    c.execute("INSERT INTO users (username, password, role) VALUES ('admin', 'S3cur3P@ss!', 'admin')")
    c.execute("INSERT INTO users (username, password, role) VALUES ('guest', 'guest123', 'user')")

    c.execute('''
    CREATE TABLE products (
        id INTEGER PRIMARY KEY,
        name TEXT,
        price REAL,
        category TEXT,
        in_stock BOOLEAN
    )
    ''')

    products = [
        ("Wireless Router Pro", 89.99, "Networking", 1),
        ("Managed Switch 24-Port", 159.95, "Networking", 1),
        ("USB-C Hub 7-in-1", 34.50, "Peripherals", 1),
        ("Mechanical Keyboard", 74.99, "Peripherals", 1),
        ("Server Rack 42U", 429.00, "Infrastructure", 0),
        ("UPS Battery Backup", 189.99, "Infrastructure", 1),
        ("Cat6 Cable 100ft", 22.50, "Cables", 1),
        ("SFP+ Transceiver", 45.00, "Networking", 1),
    ]
    c.executemany('INSERT INTO products (name, price, category, in_stock) VALUES (?, ?, ?, ?)', products)

    conn.commit()
    conn.close()

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
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT name, price, category FROM products WHERE in_stock = 1")
    products = c.fetchall()
    conn.close()
    return render_template("index.html", products=products)

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            result = c.execute(query).fetchone()

            if result:
                session["logged_in"] = True
                session["username"] = result[1]
                session["role"] = result[3]
                return redirect("/dashboard")
            else:
                error = "Invalid credentials."
        except Exception as e:
            error = f"Database error: {e}"
        finally:
            conn.close()

    return render_template("login.html", error=error)

@app.route("/dashboard")
def dashboard():
    if not session.get("logged_in"):
        return redirect("/login")

    flag = None
    if session.get("role") == "admin":
        flag = read_flag()

    return render_template("dashboard.html", username=session.get("username"), role=session.get("role"), flag=flag)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
