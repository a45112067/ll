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
import logging
import secrets
import hmac
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from functools import partial

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "db.json")
CONFIG_PATH = os.path.join(DATA_DIR, "config.json")
AUDIT_PATH = os.path.join(DATA_DIR, "audit.log")

# ---- سياسات الأمان ----
SESSION_TTL = 24 * 3600            # صلاحية الجلسة 24 ساعة
MAX_BODY = 512 * 1024              # حد أقصى للطلب الوارد 512KB
PBKDF2_ITER = 200_000              # تكرارات تجزئة كلمة المرور
LOCK_THRESHOLD = 5                 # فشل محاولات قبل القفل
LOCK_SECONDS = 900                 # مدة القفل 15 دقيقة
AUDIT_ENABLED = True

# ---- سجل مراجعة للأحداث الأمنية ----
def audit(event, detail="", remote=""):
    if not AUDIT_ENABLED:
        return
    try:
        line = json.dumps({
            "t": int(time.time()),
            "ev": event,
            "d": detail[:500],
            "ip": remote or "",
        }, ensure_ascii=False)
        with io.open(AUDIT_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


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
        cfg = {
            "admin_user": "admin",
            "admin_pass_hash": hash_password("admin"),
            "session_secret": secrets.token_urlsafe(32),
        }
        save_json(CONFIG_PATH, cfg)
    if "session_secret" not in cfg:
        cfg["session_secret"] = secrets.token_urlsafe(32)
        save_json(CONFIG_PATH, cfg)
    if "admin_user" not in cfg:
        cfg["admin_user"] = "admin"
        save_json(CONFIG_PATH, cfg)
    return cfg


def save_config(cfg):
    save_json(CONFIG_PATH, cfg)


# ---- تجزئة كلمة المرور: PBKDF2 بطيئة وآمنة (بديل SHA-256 السريع القابل للتصدّع) ----
def hash_password(pw):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, PBKDF2_ITER)
    return "pbkdf2$%d$%s$%s" % (PBKDF2_ITER, salt.hex(), dk.hex())


def verify_password(pw, stored):
    if not stored:
        return False
    try:
        # التوافق مع الهاشات القديمة (sha256 الخام) إن وُجدت
        if not stored.startswith("pbkdf2"):
            return hmac.compare_digest(hashlib.sha256(pw.encode("utf-8")).hexdigest(), stored)
        _, it, salt_hex, dk_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), bytes.fromhex(salt_hex), int(it))
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


# ---- الجلسات الموقّعة ذات الصلاحية الزمنية ----
def make_session(user, cfg):
    now = int(time.time())
    payload = "%s|%d" % (user, now + SESSION_TTL)
    sig = hmac.new(cfg["session_secret"].encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).digest()
    token = payload + "." + base64.urlsafe_b64encode(sig).decode("ascii")
    return token


def is_valid_session(token, cfg):
    try:
        payload, sig_b64 = token.rsplit(".", 1)
        exp = int(payload.split("|")[1])
        if exp < int(time.time()):
            return False
        expect = hmac.new(cfg["session_secret"].encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).digest()
        got = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
        return hmac.compare_digest(expect, got)
    except Exception:
        return False


def authorized(headers, cfg):
    h = headers.get("Authorization", "")
    if h.startswith("Bearer "):
        return is_valid_session(h[7:].strip(), cfg)
    return False


def next_id(posts):
    used = set(p.get("id") for p in posts)
    i = 1
    while "p{}".format(i) in used:
        i += 1
    return "p{}".format(i)


# ---- حجب أدوات الفحص: أنماط حقن/اختراق مجهولة تُخصم من كل الطلبات ----
# هذه حماية من الـ bots و أدوات فحص (nabruz). لا تُرضي الخادم.
ATTACK_PATTERNS = (
    "select ", "union ", "drop ", "insert ", "update(",
    "<script", "javascript:", "onerror=", "onload=", "' or '",
    "or 1=1", "1=1--", "admin'--", "../../../", "%2e%2e%2f",
    "etc/passwd", "base64", "eval(", "document.cookie",
    "/wp-admin", "/wp-login", "/.env", "/config.json", ".php?",
    "@xploit", "nuclei", "sqlmap", "dirsearch", "nikto",
)


def looks_like_attack(text):
    low = urllib.parse.unquote_plus(text or "").lower()
    return any(p in low for p in ATTACK_PATTERNS)


# ---------- المكوّن ----------
class CMSHandler(BaseHTTPRequestHandler):
    server_version = "AhmedSite/1.0"

    # سجّل (مقتضب) بدلاً من الصمت الكامل: نراقب الأحداث المهمة فقط
    def log_message(self, fmt, *args):
        pass

    def _send_bytes(self, code, data, ctype="application/json; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; img-src 'self' data: https:; "
                         "style-src 'self' 'unsafe-inline' https:; "
                         "script-src 'self' 'unsafe-inline' https:; "
                         "connect-src 'self' https:; frame-ancestors 'none'")
        self.send_header("X-XSS-Protection", "1; mode=block")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self._send_bytes(code, body)

    def _text(self, code, s):
        self._send_bytes(code, s.encode("utf-8"), "text/plain; charset=utf-8")

    def _read_json_safely(self):
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length > MAX_BODY:
                return None, "payload_too_large"
            if length == 0:
                return {}, None
            raw = self.rfile.read(length).decode("utf-8")
            try:
                obj = json.loads(raw)
            except Exception:
                return None, "invalid_json"
            if not isinstance(obj, dict):
                return None, "expected_object"
            return obj, None
        except Exception:
            return None, "read_error"

    def _parse_path(self):
        parsed = urllib.parse.urlparse(self.path)
        return parsed.path

    def _unauthorized(self):
        audit("auth_denied", "unauthorized", self.client_address[0] if self.client_address else "")
        self._json(403, {"ok": False, "error": "unauthorized"})

    # ---------- file الثابتة (مع تحصين Path Traversal + حماية config/db) ----------
    def serve_static(self, path):
        if ".." in path or "%2e" in path.lower():
            audit("path_traversal", path[:300], self._client_ip())
            return self._text(403, "Forbidden")
        target = path.lstrip("/")

        # منع إفشاء ملفات البيانات الحساسة أو ملفات الإعداد
        HIDDEN = ("data/", "config", ".db.json", "audit.log", "firestore.rules",
                  "server.py", ".git", "wp-config", ".env", "SETUP-")
        low = target.lower()
        for h in HIDDEN:
            if h.lower() in low:
                return self._text(404, "Not Found")

        if not target:
            target = "index.html"
        full = os.path.realpath(os.path.join(BASE_DIR, target))
        # مراجعة مزدوجة ضد الخروج خارج BASE_DIR
        if not (full + os.sep).startswith(os.path.realpath(BASE_DIR) + os.sep):
            return self._text(403, "Forbidden")
        if not os.path.isfile(full):
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
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _client_ip(self):
        fwd = self.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[0].strip()
        if self.client_address:
            return self.client_address[0]
        return ""

    # ---- حجب أدوات الفحص والتنزيل والتحليل ----
    _raw_ua = None

    # حدّ أقصى للطلبات المتسارعة (ضد أدوات إحصاء الصفحات و brute-force)
    _req_log = {}

    def _rate_limited(self):
        ip = self._client_ip()
        now = time.time()
        rec = self._req_log.setdefault(ip, {"n": 0, "t": now})
        # إعادة التصفير بعد نافذة زمنية
        if now - rec["t"] > 5:
            rec["n"] = 0
            rec["t"] = now
        rec["n"] += 1
        if rec["n"] > 40:
            audit("rate_blocked", "ip={}".format(ip), ip)
            return True
        return False

    def _reject_tool(self):
        ua = (self.headers.get("User-Agent") or "").lower()
        self._raw_ua = ua
        # وكلاء معرويف للماسحين وأدوات الهجوم والتنزيل
        BAD = (
            "sqlmap", "nikto", "nmap", "masscan", "zgrab", "wpscan",
            "nuclei", "metasploit", "burp", "acunetix", "netsparker",
            "dirbuster", "dirb", "gobuster", "ffuf", "wfuzz", "joomscan",
            "nessus", "openvas", "arachni", "xsser", "hydra", "medusa",
            "patator", "hashcat", "john", "aircrack", "amass", "subfinder",
            "curl", "wget", "python-requests", "python-urllib", "go-http-client",
            "okhttp", "apachebench", "ab/", "kali", "parrot", "havij",
            "pangolin", "sslscan", "testssl", "nikto", "dotdotpwn",
            "w3af", "skipfish", "fimap", "sqliv", "sql-scan", "hydra",
            "monitoba", "maxicon", "whatweb", "wayback", "commoncrawl",
            "scrapy", "python-scrapy", "mechanize", "twisted", "aiohttp",
            "headless", "phantomjs", "selenium", "net/http",
        )
        for b in BAD:
            if b and b in ua.lower():
                audit("bot_blocked", ua[:120], self._client_ip())
                return True
        return False

    # ---------- التوزيع السفلي ----------
    def do_GET(self):
        if self._rate_limited():
            return self._text(429, "Too Many Requests")
        if self._reject_tool():
            return self._text(403, "Blocked")
        if looks_like_attack(self.path):
            audit("probe_blocked", self.path[:300], self._client_ip())
            return self._text(403, "Blocked")
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
        if self._reject_tool():
            return self._text(403, "Blocked")
        if looks_like_attack(self.path):
            audit("probe_blocked", self.path[:300], self._client_ip())
            return self._text(403, "Blocked")
        path = self._parse_path()
        body, berr = self._read_json_safely()
        cfg = load_config()
        if path == "/api/login":
            return self._login(body, cfg)
        if path == "/api/password":
            if not authorized(self.headers, cfg):
                return self._unauthorized()
            pw = (body or {}).get("password", "") if isinstance(body, dict) else ""
            if len(pw) < 8:
                return self._json(400, {"ok": False, "error": "weak_password"})
            cfg["admin_pass_hash"] = hash_password(pw)
            save_config(cfg)
            audit("password_changed", "", self._client_ip())
            return self._json(200, {"ok": True})
        if path == "/api/posts":
            if not authorized(self.headers, cfg):
                return self._unauthorized()
            if berr:
                return self._json(400, {"ok": False, "error": berr})
            db = load_db()
            post = body
            post["id"] = next_id(db["posts"])
            post.setdefault("date", time.strftime("%Y-%m-%d"))
            post.setdefault("status", "published")
            post.setdefault("tags", [])
            post.setdefault("image", "")
            db["posts"].insert(0, post)
            save_db(db)
            audit("post_created", post["id"], self._client_ip())
            return self._json(201, {"ok": True, "post": post})
        self._json(404, {"ok": False, "error": "not_found"})

    # ---- دخول مراقَب مع Rate-limit (قفل مؤقت بعد فشل متكرر) ----
    _login_attempts = {}

    def _login(self, body, cfg):
        ip = self._client_ip()
        now = time.time()
        rec = self._login_attempts.get(ip)
        if rec:
            if rec["failed"] >= LOCK_THRESHOLD:
                if now - rec["t"] < LOCK_SECONDS:
                    audit("login_locked", ip, ip)
                    return self._json(429, {"ok": False, "error": "too_many_attempts"})
                self._login_attempts.pop(ip, None)
        if not isinstance(body, dict):
            return self._json(400, {"ok": False, "error": "invalid_body"})
        user = str(body.get("username", ""))[:200]
        pw = str(body.get("password", ""))[:200]
        ok = (hmac.compare_digest(user, cfg.get("admin_user", "")) and
              verify_password(pw, cfg.get("admin_pass_hash", "")))
        if ok:
            self._login_attempts.pop(ip, None)
            token = make_session(user, cfg)
            audit("login_ok", user, ip)
            return self._json(200, {"ok": True, "token": token})
        rec = self._login_attempts.setdefault(ip, {"failed": 0, "t": now})
        rec["failed"] += 1
        rec["t"] = now
        audit("login_failed", user, ip)
        return self._json(401, {"ok": False, "error": "invalid_credentials"})

    def do_PUT(self):
        path = self._parse_path()
        cfg = load_config()
        if not authorized(self.headers, cfg):
            return self._unauthorized()
        body, berr = self._read_json_safely()
        db = load_db()
        if path == "/api/site":
            merged = dict(db["site"])
            merged.update((body or {}).get("site", {}))
            db["site"] = merged
            save_db(db)
            return self._json(200, {"ok": True, "site": db["site"]})
        if path.startswith("/api/posts/"):
            pid = urllib.parse.unquote(path[len("/api/posts/"):])
            for i, p in enumerate(db["posts"]):
                if p.get("id") == pid:
                    updated = dict(p)
                    updated.update(body or {})
                    updated["id"] = pid
                    db["posts"][i] = updated
                    save_db(db)
                    audit("post_updated", pid, self._client_ip())
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
            audit("post_deleted", pid, self._client_ip())
            return self._json(200, {"ok": True})
        self._json(404, {"ok": False, "error": "not_found"})

    def do_HEAD(self):
        path = self._parse_path()
        if ".." not in path and "%2e%2e%2f" not in path.lower():
            target = path.lstrip("/") or "index.html"
            full = os.path.realpath(os.path.join(BASE_DIR, target))
            if full.startswith(os.path.realpath(BASE_DIR)) and os.path.isfile(full):
                self.send_response(200)
                self.send_header("Content-Length", str(os.path.getsize(full)))
                self.send_header("X-Content-Type-Options", "nosniff")
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
    print("      لوحة الإدارة:  http://{}:{}/m2wymu.html".format(host, port))
    print("      المدونة:       http://{}:{}/blog.html".format(host, port))
    print("      [Ctrl+C] للإيقاف")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] تم الإيقاف.")
    httpd.server_close()


if __name__ == "__main__":
    main()