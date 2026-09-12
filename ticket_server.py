#!/usr/bin/env python3
import datetime
import json
import os
import secrets
import sys
import threading
import uuid
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import unquote, urlsplit

ROOT = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get("TICKET_DB_PATH", os.path.join(ROOT, "tickets.json"))
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
if not ADMIN_PASSWORD:
    raise RuntimeError("ADMIN_PASSWORD environment variable is required")
PORT = int(os.environ.get("PORT", sys.argv[1] if len(sys.argv) > 1 else "8080"))
MAX_BODY = 12 * 1024 * 1024
ADMIN_TOKEN_TTL = 12 * 60 * 60

_db_lock = threading.Lock()
_admin_tokens = {}
_admin_lock = threading.Lock()


def load():
    with _db_lock:
        try:
            with open(DB, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return []


def save(items):
    os.makedirs(os.path.dirname(DB) or ".", exist_ok=True)
    tmp = DB + ".tmp"
    with _db_lock:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(items, f, ensure_ascii=False, indent=2)
        os.replace(tmp, DB)


def now():
    return datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")


def ticket_id_from_path(path):
    parts = [unquote(x).strip() for x in urlsplit(path).path.split("/") if x]
    try:
        i = parts.index("tickets")
    except ValueError:
        return ""
    return parts[i + 1] if i + 1 < len(parts) else ""


def cleanup_admin_tokens():
    cutoff = datetime.datetime.now().timestamp()
    with _admin_lock:
        for token, expires in list(_admin_tokens.items()):
            if expires <= cutoff:
                _admin_tokens.pop(token, None)


def new_admin_token():
    cleanup_admin_tokens()
    token = secrets.token_urlsafe(32)
    with _admin_lock:
        _admin_tokens[token] = datetime.datetime.now().timestamp() + ADMIN_TOKEN_TTL
    return token


def valid_admin_token(token):
    if not token:
        return False
    cleanup_admin_tokens()
    with _admin_lock:
        expires = _admin_tokens.get(token)
    return bool(expires and expires > datetime.datetime.now().timestamp())


class H(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def auth_admin(self):
        return valid_admin_token(self.headers.get("X-Admin-Token", ""))

    def body(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("Invalid Content-Length")
        if n < 0 or n > MAX_BODY:
            raise ValueError("Request body is too large")
        raw = self.rfile.read(n)
        return json.loads(raw or b"{}")

    def do_GET(self):
        if self.path == "/api/health":
            return self._json(200, {"ok": True, "service": "AASHIQ Ticket Server"})

        if self.path.startswith("/api/tickets/"):
            tid = ticket_id_from_path(self.path)
            owner = self.headers.get("X-Owner-Token", "")
            admin = self.auth_admin()
            tickets = load()
            ticket = next((x for x in tickets if str(x.get("id", "")).strip() == tid), None)
            if not ticket:
                return self._json(404, {"error": "Ticket not found"})
            if not admin and ticket.get("ownerToken") != owner:
                return self._json(403, {"error": "Access denied"})
            return self._json(200, {"ticket": ticket})

        if self.path == "/api/tickets":
            owner = self.headers.get("X-Owner-Token", "")
            admin = self.auth_admin()
            tickets = load()
            if admin:
                return self._json(200, {"tickets": tickets})
            return self._json(200, {"tickets": [x for x in tickets if x.get("ownerToken") == owner]})

        return super().do_GET()

    def do_POST(self):
        try:
            data = self.body()
        except (ValueError, json.JSONDecodeError):
            return self._json(400, {"error": "Invalid request body"})

        if self.path == "/api/admin/login":
            password = str(data.get("password", ""))
            if not secrets.compare_digest(password, ADMIN_PASSWORD):
                return self._json(401, {"error": "Incorrect admin password"})
            return self._json(200, {
                "ok": True,
                "token": new_admin_token(),
                "expiresIn": ADMIN_TOKEN_TTL
            })

        if self.path == "/api/tickets":
            owner = self.headers.get("X-Owner-Token", "")
            if not owner:
                return self._json(400, {"error": "Owner token missing"})
            if not data.get("name") or not data.get("message"):
                return self._json(400, {"error": "Name and issue/message are required"})

            ticket = {
                "id": "TKT-" + uuid.uuid4().hex[:6].upper(),
                "name": data.get("name", ""),
                "contact": data.get("contact", ""),
                "uid": data.get("uid", ""),
                "utr": data.get("utr", ""),
                "paymentProof": data.get("paymentProof", ""),
                "paymentProofName": data.get("paymentProofName", ""),
                "message": data.get("message", ""),
                "createdAt": now(),
                "status": "Created",
                "ownerToken": owner,
                "messages": [],
            }
            tickets = load()
            tickets.insert(0, ticket)
            save(tickets)
            return self._json(200, ticket)

        if self.path.startswith("/api/tickets/") and self.path.endswith("/messages"):
            parts = [unquote(x).strip() for x in urlsplit(self.path).path.split("/") if x]
            tid = parts[-2] if len(parts) >= 2 and parts[-1] == "messages" else ""
            admin = self.auth_admin()
            owner = self.headers.get("X-Owner-Token", "")
            tickets = load()
            ticket = next((x for x in tickets if str(x.get("id", "")).strip() == tid), None)
            if not ticket:
                return self._json(404, {"error": "Ticket not found"})
            if not admin and ticket.get("ownerToken") != owner:
                return self._json(403, {"error": "Access denied"})
            if ticket.get("status") == "Closed":
                return self._json(409, {"error": "This ticket is closed. Reopen it from Admin before sending new messages."})

            msg = {
                "sender": "admin" if admin else "member",
                "ownerToken": ticket.get("ownerToken") if not admin else "admin",
                "text": data.get("text", ""),
                "fileData": data.get("fileData", ""),
                "fileName": data.get("fileName", ""),
                "createdAt": now(),
            }
            if not msg["text"] and not msg["fileData"]:
                return self._json(400, {"error": "Message or attachment required"})
            ticket.setdefault("messages", []).append(msg)
            save(tickets)
            return self._json(200, {"ok": True, "ticket": ticket})

        return self._json(404, {"error": "Not found"})

    def do_PATCH(self):
        if not self.path.startswith("/api/tickets/"):
            return self._json(404, {"error": "Not found"})

        try:
            data = self.body()
        except (ValueError, json.JSONDecodeError):
            return self._json(400, {"error": "Invalid request body"})

        tid = ticket_id_from_path(self.path)
        tickets = load()
        ticket = next((x for x in tickets if str(x.get("id", "")).strip() == tid), None)
        if not ticket:
            return self._json(404, {"error": "Ticket not found"})

        admin = self.auth_admin()
        owner = self.headers.get("X-Owner-Token", "")
        if admin:
            if data.get("status") in ("Created", "In Progress", "Resolved", "Closed"):
                ticket["status"] = data["status"]
                save(tickets)
                return self._json(200, ticket)
            return self._json(400, {"error": "Invalid status"})

        if ticket.get("ownerToken") != owner:
            return self._json(403, {"error": "Access denied"})
        if data.get("status") == "Closed":
            ticket["status"] = "Closed"
            save(tickets)
            return self._json(200, ticket)
        return self._json(403, {"error": "Only Admin can change this ticket status"})


if __name__ == "__main__":
    os.makedirs(os.path.dirname(DB) or ".", exist_ok=True)
    print(f"AASHIQ Ticket Server running on http://0.0.0.0:{PORT}")
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
