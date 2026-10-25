"""CSRF protection: signed double-submit token.

Strategy: a per-session token is stored in a (non-HttpOnly, SameSite=Lax)
cookie AND echoed into every state-changing request, either as a hidden
``csrf_token`` form field (server-rendered forms) or an ``X-CSRF-Token``
header (same-origin fetch). The middleware requires the submitted token to
match the cookie token. The token is HMAC-signed with the app secret so it
cannot be forged or set by a cross-site attacker (cookie-tossing resistant).
"""
import base64
import hashlib
import hmac
import json
import secrets
import urllib.parse

from . import config

COOKIE_NAME = "csrf_token"
_MAX_AGE = 60 * 60 * 8  # match auth token TTL


def _sign(raw: str) -> str:
    mac = hmac.new(config.SECRET.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{raw}.{mac}"


def generate_token() -> str:
    """Return a fresh signed CSRF token."""
    raw = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    return _sign(raw)


def _unsign(token: str):
    """Return the raw payload if the signature is valid, else None."""
    if not token or not isinstance(token, str) or "." not in token:
        return None
    raw, _, mac = token.rpartition(".")
    expected = hmac.new(config.SECRET.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).hexdigest()
    if hmac.compare_digest(expected, mac):
        return raw
    return None


def valid_token(token: str) -> bool:
    """True if the token is a well-formed, correctly signed token."""
    return _unsign(token) is not None


def tokens_match(provided: str, expected: str) -> bool:
    """Constant-time compare of two (signed) tokens."""
    if not provided or not expected:
        return False
    return hmac.compare_digest(str(provided), str(expected))


def _header_token(headers) -> str | None:
    for k, v in headers or []:
        if k.lower() == b"x-csrf-token" and v:
            return v.decode("utf-8") if isinstance(v, (bytes, bytearray)) else str(v)
    return None


def _body_token(body: bytes) -> str | None:
    if not body:
        return None
    try:
        text = body.decode("utf-8", "replace")
    except Exception:
        return None
    text_stripped = text.lstrip()
    # JSON body
    if text_stripped.startswith("{"):
        try:
            data = json.loads(text)
            if isinstance(data, dict) and data.get("csrf_token"):
                return str(data["csrf_token"])
        except Exception:
            pass
    # urlencoded body
    if "=" in text and "&" in text or "=" in text:
        for pair in text.split("&"):
            if pair.startswith("csrf_token="):
                return urllib.parse.unquote(pair[len("csrf_token="):])
    return None


def submitted_token(scope, body: bytes) -> str | None:
    """Extract the CSRF token from the request header, else the body."""
    return _header_token(scope.get("headers", [])) or _body_token(body)


def cookie_token(scope, name: str = COOKIE_NAME) -> str | None:
    """Read the CSRF cookie value from the request headers."""
    for k, v in scope.get("headers", []):
        if k.lower() == b"cookie" and v:
            hdr = v.decode("utf-8") if isinstance(v, (bytes, bytearray)) else str(v)
            for pair in hdr.split(";"):
                pair = pair.strip()
                if pair.startswith(name + "="):
                    return urllib.parse.unquote(pair[len(name) + 1:])
    return None


def check(scope, body: bytes) -> bool:
    """Return True if the request carries a valid token matching the cookie."""
    cookie_tok = cookie_token(scope)
    if not cookie_tok or not valid_token(cookie_tok):
        return False
    provided = submitted_token(scope, body)
    return provided is not None and tokens_match(provided, cookie_tok)
