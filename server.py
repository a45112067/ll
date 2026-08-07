# -*- coding: utf-8 -*-
"""
أحمد أيمن يحيى - موقع شخصي
خادم HTTP خفيف (بدون معتمادات خارجية) يخدم الملفات الثابتة + REST API
للمدونة ولوحة الإدارة، مع تخزين في ملف JSON.

التشغيل:  py -3 server.py   ثم افتح  http://localhost:8000
"""
import os
import io
import time
import json
import base64
import hashlib
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from functools import partial

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "db.json")
CONFIG_PATH = os.path.join(DATA_DIR, "config.json")


# ---------- أدوات JSON ----------
def load_json(path, default=None):
    if not os.path.exists(path):
        return default
    try:
        with io.open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with io.open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    if os.path.exists(path):
        os.replace(tmp, path)
    else:
        os.rename(tmp, path)


def load_db():
    db = load_json(DB_PATH, None)
    if not isinstance(db, dict):
        db = {}
    db.setdefault("site", {})
    db.setdefault("posts", [])
    return db


def save_db(db):
    save_json(DB_PATH, db)


def load_config():
    cfg = load_json(CONFIG_PATH, None)
    if not isinstance(cfg, dict):
        secret = base64.b64encode(os.urandom(24)).decode("ascii")
        cfg = {
            "admin_user": "admin",
            "admin_pass_hash": hash_password("admin"),
            "session_secret": secret,
        }
        save_json(CONFIG_PATH, cfg)
    if "session_secret" not in cfg:
        cfg["session_secret"] = base64.b64encode(os.urandom(24)).decode("ascii")
        save_json(CONFIG_PATH, cfg)
    return cfg


def save_config(cfg):
    save_json(CONFIG_PATH, cfg)


def hash_password(pw):
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()


def make_session(user, cfg):
    raw = "{}|{}|{}".format(user, cfg["session_secret"], int(time.time()))
    return base64.b64encode(raw.encode("utf-8")).decode("ascii")


def is_valid_session(token, cfg):
    try:
        raw = base64.b64decode(token.encode("ascii")).decode("utf-8")
        parts = raw.split("|")
        if len(parts) != 3:
            return False
        return parts[1] == cfg["session_secret"]
    except Exception:
        return False


def authorized(headers, cfg):
    h = headers.get("Authorization", "")
    if h.startswith("Bearer "):
        return is_valid_session(h[7:], cfg)
    return False


def next_id(posts):
    used = set(p.get("id") for p in posts)
    i = 1
    while "p{}".format(i) in used:
        i += 1
    return "p{}".format(i)


# ---------- المكوّن ----------
class CMSHandler(BaseHTTPRequestHandler):
    server_version = "AhmedSite/1.0"

    # ---------- مساعدات الرد ----------
    def log_message(self, fmt, *args):
        pass

    def _send_bytes(self, code, data, ctype="application/json; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self._send_bytes(code, body)

    def _text(self, code, s):
        self._send_bytes(code, s.encode("utf-8"), "text/plain; charset=utf-8")

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length == 0:
                return {}
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            return {}

    def _parse_path(self):
        parsed = urllib.parse.urlparse(self.path)
        return parsed.path

    def _unauthorized(self):
        self._json(403, {"ok": False, "error": "unauthorized"})

    # ---------- الملفات الثابتة ----------
    def serve_static(self, path):
        if ".." in path:
            return self._text(403, "Forbidden")
        target = path.lstrip("/")
        if not target:
            target = "index.html"
        full = os.path.normpath(os.path.join(BASE_DIR, target))
        if not full.startswith(BASE_DIR) or not os.path.isfile(full):
            return self._text(404, "404 - Not Found")
        ext = os.path.splitext(full)[1].lower()
        ctype = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".json": "application/json; charset=utf-8",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".gif": "image/gif",
            ".svg": "image/svg+xml",
            ".webp": "image/webp",
            ".ico": "image/x-icon",
            ".pdf": "application/pdf",
        }.get(ext, "application/octet-stream")
        with io.open(full, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ---------- التوزيع السفلي ----------
    def do_GET(self):
        path = self._parse_path()
        if path == "/api/health":
            return self._json(200, {"ok": True, "time": time.time()})
        if path == "/api/site":
            db = load_db()
            return self._json(200, {"ok": True, "site": db["site"]})
        if path == "/api/posts":
            db = load_db()
            return self._json(200, {"ok": True, "posts": db["posts"]})
        if path.startswith("/api/posts/"):
            pid = urllib.parse.unquote(path[len("/api/posts/"):])
            db = load_db()
            post = next((p for p in db["posts"] if p.get("id") == pid), None)
            if not post:
                return self._json(404, {"ok": False, "error": "not_found"})
            return self._json(200, {"ok": True, "post": post})
        self.serve_static(path)

    def do_POST(self):
        path = self._parse_path()
        body = self._read_json()
        cfg = load_config()
        if path == "/api/login":
            user = body.get("username", "")
            pw = body.get("password", "")
            if (user == cfg.get("admin_user") and
                    hash_password(pw) == cfg.get("admin_pass_hash")):
                token = make_session(user, cfg)
                return self._json(200, {"ok": True, "token": token})
            return self._json(401, {"ok": False, "error": "invalid_credentials"})
        if path == "/api/password":
            if not authorized(self.headers, cfg):
                return self._unauthorized()
            pw = body.get("password", "")
            if len(pw) < 4:
                return self._json(400, {"ok": False, "error": "weak_password"})
            cfg["admin_pass_hash"] = hash_password(pw)
            save_config(cfg)
            return self._json(200, {"ok": True})
        if path == "/api/posts":
            if not authorized(self.headers, cfg):
                return self._unauthorized()
            db = load_db()
            post = body
            post["id"] = next_id(db["posts"])
            post.setdefault("date", time.strftime("%Y-%m-%d"))
            post.setdefault("status", "published")
            post.setdefault("tags", [])
            post.setdefault("image", "")
            db["posts"].insert(0, post)
            save_db(db)
            return self._json(201, {"ok": True, "post": post})
        self._json(404, {"ok": False, "error": "not_found"})

    def do_PUT(self):
        path = self._parse_path()
        cfg = load_config()
        if not authorized(self.headers, cfg):
            return self._unauthorized()
        body = self._read_json()
        db = load_db()
        if path == "/api/site":
            merged = dict(db["site"])
            merged.update(body.get("site", {}))
            db["site"] = merged
            save_db(db)
            return self._json(200, {"ok": True, "site": db["site"]})
        if path.startswith("/api/posts/"):
            pid = urllib.parse.unquote(path[len("/api/posts/"):])
            for i, p in enumerate(db["posts"]):
                if p.get("id") == pid:
                    updated = dict(p)
                    updated.update(body)
                    updated["id"] = pid
                    db["posts"][i] = updated
                    save_db(db)
                    return self._json(200, {"ok": True, "post": updated})
            return self._json(404, {"ok": False, "error": "not_found"})
        self._json(404, {"ok": False, "error": "not_found"})

    def do_DELETE(self):
        path = self._parse_path()
        cfg = load_config()
        if not authorized(self.headers, cfg):
            return self._unauthorized()
        if path.startswith("/api/posts/"):
            pid = urllib.parse.unquote(path[len("/api/posts/"):])
            db = load_db()
            before = len(db["posts"])
            db["posts"] = [p for p in db["posts"] if p.get("id") != pid]
            if len(db["posts"]) == before:
                return self._json(404, {"ok": False, "error": "not_found"})
            save_db(db)
            return self._json(200, {"ok": True})
        self._json(404, {"ok": False, "error": "not_found"})

    def do_HEAD(self):
        path = self._parse_path()
        if ".." not in path:
            target = path.lstrip("/") or "index.html"
            full = os.path.normpath(os.path.join(BASE_DIR, target))
            if full.startswith(BASE_DIR) and os.path.isfile(full):
                self.send_response(200)
                self.send_header("Content-Length", str(os.path.getsize(full)))
                self.end_headers()
                return
        self.send_response(404)
        self.end_headers()


# ---------- نقطة البداية ----------
def main():
    host = "127.0.0.1"
    port = 8000
    handler = partial(CMSHandler)
    httpd = ThreadingHTTPServer((host, port), handler)
    print("[OK] خادم أحمد أيمن يعمل على:")
    print("      http://{}:{}".format(host, port))
    print("      لوحة الإدارة:  http://{}:{}/admin.html".format(host, port))
    print("      المدونة:       http://{}:{}/blog.html".format(host, port))
    print("      [Ctrl+C] للإيقاف")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] تم الإيقاف.")
    httpd.server_close()


if __name__ == "__main__":
    main()