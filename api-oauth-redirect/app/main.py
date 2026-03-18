from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from flask import Flask, render_template, request, jsonify
import os, uuid, secrets, time

app = Flask(__name__)

FLAG_PATH = os.path.join(os.path.dirname(__file__), "flag.txt")

# ---------------------------------------------------------------------------
# In-memory data stores
# ---------------------------------------------------------------------------
CLIENTS = {}    # client_id -> {name, redirect_uri, secret}
USERS = {}      # username -> {username, password, role, email, profile_data}
AUTH_CODES = {} # code -> {client_id, redirect_uri, user, expires_at}
TOKENS = {}     # token -> {client_id, user, expires_at}

# ---------------------------------------------------------------------------
# Initialisation — seed clients, users, write flag
# ---------------------------------------------------------------------------

def init_lab():
    if os.path.exists(FLAG_PATH):
        os.remove(FLAG_PATH)

    flag = f"KX{{{uuid.uuid4().hex[:16]}}}"
    with open(FLAG_PATH, "w") as f:
        f.write(flag)

    # --- OAuth2 Client --------------------------------------------------------
    CLIENTS["webapp-001"] = {
        "name": "CorpWebApp",
        "redirect_uri": "http://app.local/callback",
        "secret": "webapp-secret-2025",
    }

    # --- Users ----------------------------------------------------------------
    USERS["admin"] = {
        "username": "admin",
        "password": "admin",
        "role": "admin",
        "email": "admin@corp.local",
        "profile_data": {
            "full_name": "System Administrator",
            "department": "IT Security",
            "employee_id": "EMP-0001",
            "internal_notes": f"Service account flag: {flag}",
            "access_level": "superadmin",
            "last_login": "2025-12-01T08:30:00Z",
        },
    }
    USERS["guest"] = {
        "username": "guest",
        "password": "guest2025",
        "role": "user",
        "email": "guest@corp.local",
        "profile_data": {
            "full_name": "Guest User",
            "department": "External",
            "employee_id": "EMP-9999",
            "access_level": "readonly",
        },
    }

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def generate_auth_code():
    return secrets.token_urlsafe(24)


def generate_access_token():
    return secrets.token_urlsafe(32)


def build_delivery_url(redirect_uri: str, code: str, state: str) -> str:
    separator = "&" if "?" in redirect_uri else "?"
    delivery_url = f"{redirect_uri}{separator}code={code}"
    if state:
        delivery_url += f"&state={state}"
    return delivery_url


def get_bearer_token():
    """Extract and validate Bearer token from Authorization header."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token_value = auth[7:]
        token_data = TOKENS.get(token_value)
        if token_data and token_data["expires_at"] > time.time():
            return token_data
    return None

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/oauth/authorize", methods=["GET"])
def oauth_authorize():
    """
    OAuth2 Authorization Endpoint (simplified — auto-approves for admin).

    VULNERABILITY: redirect_uri is validated using startswith() which is a
    prefix-only check. An attacker can craft a URI like:
        http://app.local/callback@evil.com/steal
    which passes the startswith("http://app.local/callback") check but the
    HTTP client delivering the authorization code treats "app.local" as a
    userinfo component and actually connects to evil.com.
    """
    response_type = request.args.get("response_type", "")
    client_id = request.args.get("client_id", "")
    redirect_uri = request.args.get("redirect_uri", "")
    state = request.args.get("state", "")

    # --- Validate response_type -----------------------------------------------
    if response_type != "code":
        return jsonify({"error": "unsupported_response_type",
                        "error_description": "Only response_type=code is supported"}), 400

    # --- Validate client_id ---------------------------------------------------
    client = CLIENTS.get(client_id)
    if not client:
        return jsonify({"error": "invalid_client",
                        "error_description": f"Unknown client_id: {client_id}"}), 400

    # --- Validate redirect_uri ------------------------------------------------
    # BUG: prefix match only! An attacker can append anything after the
    # legitimate redirect_uri prefix to redirect the code elsewhere.
    if not redirect_uri:
        return jsonify({"error": "invalid_request",
                        "error_description": "redirect_uri is required"}), 400

    if not redirect_uri.startswith(client["redirect_uri"]):
        return jsonify({
            "error": "invalid_redirect_uri",
            "error_description": "redirect_uri does not match the registered callback",
        }), 400

    # --- Auto-approve for admin (simulates admin clicking "Approve") ----------
    code = generate_auth_code()
    AUTH_CODES[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "user": "admin",
        "expires_at": time.time() + 300,  # 5 minutes
    }

    # --- Deliver the code to redirect_uri ------------------------------------
    delivery_url = build_delivery_url(redirect_uri, code, state)
    try:
        with urlopen(delivery_url, timeout=5) as response:
            delivery_status = getattr(response, "status", 200)
    except HTTPError as exc:
        delivery_status = exc.code
    except URLError as exc:
        del AUTH_CODES[code]
        return jsonify({
            "error": "redirect_delivery_failed",
            "error_description": (
                "Failed to deliver the authorization code to the supplied redirect_uri: "
                f"{exc.reason}"
            ),
        }), 502

    return jsonify({
        "message": "Authorization successful",
        "delivery": "Authorization code delivered to redirect_uri",
        "delivery_status": delivery_status,
    })


@app.route("/oauth/token", methods=["POST"])
def oauth_token():
    """
    OAuth2 Token Endpoint — exchange authorization code for access token.
    """
    data = request.get_json(silent=True) or request.form.to_dict() or {}

    grant_type = data.get("grant_type", "")
    code = data.get("code", "")
    client_id = data.get("client_id", "")
    client_secret = data.get("client_secret", "")
    redirect_uri = data.get("redirect_uri", "")

    # --- Validate grant_type --------------------------------------------------
    if grant_type != "authorization_code":
        return jsonify({"error": "unsupported_grant_type",
                        "error_description": "Only grant_type=authorization_code is supported"}), 400

    # --- Validate client credentials ------------------------------------------
    client = CLIENTS.get(client_id)
    if not client or client["secret"] != client_secret:
        return jsonify({"error": "invalid_client",
                        "error_description": "Invalid client_id or client_secret"}), 401

    # --- Validate authorization code ------------------------------------------
    code_data = AUTH_CODES.get(code)
    if not code_data:
        return jsonify({"error": "invalid_grant",
                        "error_description": "Invalid or expired authorization code"}), 400

    if code_data["expires_at"] < time.time():
        del AUTH_CODES[code]
        return jsonify({"error": "invalid_grant",
                        "error_description": "Authorization code has expired"}), 400

    if code_data["client_id"] != client_id:
        return jsonify({"error": "invalid_grant",
                        "error_description": "Code was not issued to this client"}), 400

    if code_data["redirect_uri"] != redirect_uri:
        return jsonify({"error": "invalid_grant",
                        "error_description": "redirect_uri does not match the one used during authorization"}), 400

    # --- Issue access token ---------------------------------------------------
    del AUTH_CODES[code]  # single-use code

    access_token = generate_access_token()
    TOKENS[access_token] = {
        "client_id": client_id,
        "user": code_data["user"],
        "expires_at": time.time() + 3600,  # 1 hour
    }

    return jsonify({
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 3600,
    })


@app.route("/api/profile", methods=["GET"])
def api_profile():
    """Protected endpoint — returns the authenticated user's profile."""
    token_data = get_bearer_token()
    if not token_data:
        return jsonify({"error": "Authentication required. "
                        "Send Authorization: Bearer <access_token>"}), 401

    username = token_data["user"]
    user = USERS.get(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "profile": user["profile_data"],
    })


@app.route("/api/docs", methods=["GET"])
def api_docs():
    return jsonify({
        "service": "CorpAuth OAuth2 Authorization Server v1.0",
        "description": "OAuth2 authorization code flow for CorpWebApp",
        "oauth2_flow": {
            "step_1": {
                "description": "Initiate authorization — admin auto-approves and the code is delivered to redirect_uri",
                "method": "GET",
                "path": "/oauth/authorize",
                "parameters": {
                    "response_type": "code",
                    "client_id": "webapp-001",
                    "redirect_uri": "The callback URL registered for the client",
                    "state": "Optional CSRF protection state parameter",
                },
                "note": "The admin user auto-approves all authorization requests. "
                        "The server delivers the authorization code to redirect_uri?code=<auth_code>&state=<state>.",
            },
            "step_2": {
                "description": "Exchange authorization code for access token",
                "method": "POST",
                "path": "/oauth/token",
                "body": {
                    "grant_type": "authorization_code",
                    "code": "<authorization_code from step 1>",
                    "client_id": "webapp-001",
                    "client_secret": "webapp-secret-2025",
                    "redirect_uri": "<same redirect_uri used in step 1>",
                },
                "response": {
                    "access_token": "<token>",
                    "token_type": "bearer",
                    "expires_in": 3600,
                },
            },
            "step_3": {
                "description": "Access protected resources with the token",
                "method": "GET",
                "path": "/api/profile",
                "headers": {"Authorization": "Bearer <access_token>"},
                "note": "Returns the authenticated user's profile data.",
            },
        },
        "registered_clients": {
            "webapp-001": {
                "name": "CorpWebApp",
                "registered_redirect_uri": "http://app.local/callback",
            },
        },
    })


@app.route("/api/hint", methods=["GET"])
def api_hint():
    return jsonify({
        "hints": [
            "The OAuth2 authorization endpoint validates the redirect_uri parameter. "
            "But how strict is that validation?",
            "What happens if the redirect_uri starts with the registered callback URL "
            "but has extra characters appended?",
            "Think about URL parsing: http://app.local/callback@evil.com — "
            "where does this actually connect to?",
            "The admin auto-approves authorization requests. If you can redirect "
            "the auth code to a server you control, you can steal it.",
            "After capturing the code, use /oauth/token with the client credentials "
            "(see /api/docs) to exchange it for an access token.",
        ],
    })


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_lab()
    app.run(host="0.0.0.0", port=5000, debug=False)
