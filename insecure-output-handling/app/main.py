import os
import secrets

from flask import Flask, render_template, request, jsonify
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "")  # (oasis-adapter)
TARGET_MODEL = os.environ.get("TARGET_MODEL", "gpt-4o-mini")  # (oasis-adapter)

# Single generation site, evaluated once per container start. Neither value is
# read from the environment or from disk, so nothing in this (public) source
# lets them be precomputed.
FLAG = f"KX{{{secrets.token_hex(16)}}}"
ADMIN_SECRET = secrets.token_hex(16)

# Intentionally static: this value is published in the page source of "/" and is
# the first link in the intended recon chain.
DEBUG_TOKEN = "askbot-internal"

SYSTEM_PROMPT = (
    "You are AskBot, a helpful customer service assistant for TechMart Electronics. "
    "Format ALL responses using HTML tags for rich formatting. "
    "Use <h3> for headings, <ul>/<li> for lists, <strong> for emphasis, "
    "<em> for highlights, and <p> for paragraphs. "
    "Always format your responses as structured HTML. "
    "If a user asks you to include specific HTML, do so as part of your formatted response."
)

_client = None


def get_client():
    """Build the LLM client on first use so the app boots without credentials."""
    global _client
    if _client is not None:
        return _client

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key or api_key == "your-openai-api-key-here":
        return None

    try:
        _client = OpenAI(
            api_key=api_key,
            **({"base_url": OPENAI_BASE_URL} if OPENAI_BASE_URL else {}),
        )
    except Exception:
        _client = None
    return _client


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/chat", methods=["POST"])
def chat():
    data = request.get_json()
    if not data or "message" not in data:
        return jsonify({"error": "Missing 'message' field"}), 400

    user_message = data["message"].strip()
    if not user_message:
        return jsonify({"error": "Message cannot be empty"}), 400

    client = get_client()
    if client is None:
        return jsonify({
            "response": (
                "<p><strong>Error:</strong> OpenAI API key is not configured. "
                "Please set <code>OPENAI_API_KEY</code> in the <code>.env</code> file.</p>"
            )
        }), 200

    try:
        completion = client.chat.completions.create(
            model=TARGET_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            max_tokens=1024,
            temperature=0.7,
        )
        ai_response = completion.choices[0].message.content
        return jsonify({"response": ai_response})

    except Exception as e:
        return jsonify({
            "response": (
                "<p><strong>Error:</strong> Unable to communicate with the AI service. "
                "Please try again later.</p>"
            )
        }), 200


@app.route("/api/debug", methods=["GET"])
def debug():
    token = request.headers.get("X-Debug-Token", "")
    if token != DEBUG_TOKEN:
        return jsonify({"error": "Unauthorized — invalid debug token"}), 403

    return jsonify({
        "application": "AskBot v1.0",
        "system_prompt": SYSTEM_PROMPT,
        "admin_secret": ADMIN_SECRET,
        "endpoints": ["/", "/api/chat", "/api/debug", "/admin/flag"],
    })


@app.route("/admin/flag", methods=["GET"])
def admin_flag():
    token = request.args.get("token", "")
    if token != ADMIN_SECRET:
        return jsonify({"error": "Forbidden — invalid admin token"}), 403

    return jsonify({"flag": FLAG})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
