"""Central configuration: paths, secrets, and app constants."""
import os
import secrets

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # project root (scanforge/)
APP_DIR = os.path.dirname(os.path.abspath(__file__))                     # app/
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(APP_DIR, "static")
DATA_DIR = os.path.join(BASE_DIR, "data")
REPORT_DIR = os.path.join(DATA_DIR, "reports")

for _d in (DATA_DIR, REPORT_DIR):
    os.makedirs(_d, exist_ok=True)

DATABASE = os.path.join(DATA_DIR, "sentinel.db")

# JWT signing secret. Generated once and persisted so sessions survive restarts.
_SECRET_FILE = os.path.join(DATA_DIR, ".secret")
if os.path.exists(_SECRET_FILE):
    with open(_SECRET_FILE, "r") as fh:
        SECRET = fh.read().strip()
else:
    SECRET = secrets.token_urlsafe(48)
    with open(_SECRET_FILE, "w") as fh:
        fh.write(SECRET)

ALGORITHM = "HS256"
TOKEN_TTL_SECONDS = 60 * 60 * 8  # 8 hours

# ---- Admin bootstrap credentials -----------------------------------------
# The admin account is seeded on first run. Override the email/password with
# ADMIN_EMAIL / ADMIN_PASSWORD env vars (set these on your deploy). If no
# password is given, a strong random one is generated ONCE, saved to
# data/.admin_password, and printed to the server console/log — it never
# appears on any web page.
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@sentinel.local").strip() or "admin@sentinel.local"
_ADMIN_PW_ENV = os.environ.get("ADMIN_PASSWORD", "").strip()


def get_admin_password():
    """Return the configured admin password, minting + persisting a random
    one on first use so it survives restarts and stays off the website."""
    if _ADMIN_PW_ENV:
        return _ADMIN_PW_ENV
    pw_path = os.path.join(DATA_DIR, ".admin_password")
    if os.path.exists(pw_path):
        with open(pw_path, "r") as fh:
            pw = fh.read().strip()
        if pw:
            return pw
    pw = secrets.token_urlsafe(18)
    with open(pw_path, "w") as fh:
        fh.write(pw)
    return pw


ADMIN_PASSWORD_MINTED = not bool(_ADMIN_PW_ENV)  # True when we generated a random one

COOKIE_NAME = "sentinel_session"
# Secure cookies only over HTTPS. Off in local dev; flip on behind Render TLS
# by setting SECURE_COOKIE=true (Render serves the service over HTTPS).
_COOKIE = os.environ.get("SECURE_COOKIE", "").strip().lower()
COOKIE_SECURE = _COOKIE in ("1", "true", "yes", "on")

# Concurrency for the scan runner
MAX_CONCURRENT_SCANS = 3
SCAN_TIMEOUT_SECONDS = 600

# Default per-plan credit grants
PLAN_DEFAULTS = {
    "free": {"name": "Free", "price": 0, "credits": 10, "features": ["3 tools", "5 scans / month", "Email support"]},
    "pro": {"name": "Pro", "price": 49, "credits": 500, "features": ["All tools", "Unlimited scans", "Burp Suite + ZAP", "Priority queue", "PDF reports"]},
    "enterprise": {"name": "Enterprise", "price": 299, "credits": 10000, "features": ["All tools", "Unlimited everything", "On-prem scanner", "Dedicated manager", "SLA", "Custom integrations"]},
}

SEVERITIES = ["info", "low", "medium", "high", "critical"]
