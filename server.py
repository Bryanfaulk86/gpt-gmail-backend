import os
from flask import Flask, request, jsonify, redirect
import requests
import base64
from email.message import EmailMessage

app = Flask(__name__)

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GMAIL_SEND_URL = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"

def base64url_encode(bytestr: bytes) -> str:
    return base64.urlsafe_b64encode(bytestr).decode().rstrip("=")

@app.get("/oauth/authorize")
def oauth_authorize():
    query = request.query_string.decode("utf-8")
    return redirect(f"{GOOGLE_AUTH_URL}?{query}", code=302)

@app.post("/oauth/token")
def oauth_token():
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    body = request.get_data(as_text=True)
    resp = requests.post(GOOGLE_TOKEN_URL, data=body, headers=headers, timeout=20)
    return (resp.content, resp.status_code, {"Content-Type": resp.headers.get("Content-Type", "application/json")})

@app.post("/sendEmail")
def send_email():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify(error="Missing Bearer token"), 401
    access_token = auth.split(None, 1)[1]

    data = request.get_json(silent=True) or {}
    to = data.get("to")
    subject = data.get("subject")
    body = data.get("body")
    html = bool(data.get("html", False))

    if not to or not subject or not body:
        return jsonify(error="Missing 'to', 'subject', or 'body'"), 400

    msg = EmailMessage()
    msg["To"] = to
    msg["Subject"] = subject
    if html:
        msg.add_alternative(body, subtype="html")
    else:
        msg.set_content(body)

    raw = base64url_encode(msg.as_bytes())
    payload = {"raw": raw}

    r = requests.post(
        GMAIL_SEND_URL,
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
        json=payload,
        timeout=20
    )

    if r.status_code in (200, 202):
        try:
            rid = r.json().get("id")
        except Exception:
            rid = None
        return jsonify(ok=True, id=rid), 200

    try:
        err = r.json()
    except Exception:
        err = {"error": r.text}
    return jsonify(ok=False, **err), r.status_code

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
