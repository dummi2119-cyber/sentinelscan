"""Password hashing (PBKDF2) and JWT session tokens."""
import hashlib
import hmac
import secrets
import time

import jwt

from . import config


def hash_password(password: str):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return dk.hex(), salt.hex()


def verify_password(password: str, pw_hash: str, salt: str) -> bool:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), 200_000)
    return hmac.compare_digest(dk.hex(), pw_hash)


def create_token(uid: int, role: str) -> str:
    now = int(time.time())
    payload = {
        "sub": str(uid),
        "role": role,
        "iat": now,
        "exp": now + config.TOKEN_TTL_SECONDS,
    }
    return jwt.encode(payload, config.SECRET, algorithm=config.ALGORITHM)


def decode_token(token: str):
    try:
        return jwt.decode(token, config.SECRET, algorithms=[config.ALGORITHM])
    except jwt.PyJWTError:
        return None


def issue_cookie(uid: int, role: str):
    return create_token(uid, role)


def token_user(token: str):
    """Return a small dict {id, role} if the token is valid, else None."""
    payload = decode_token(token)
    if not payload:
        return None
    sub = payload.get("sub")
    try:
        sub = int(sub)
    except (TypeError, ValueError):
        pass
    return {"id": sub, "role": payload.get("role")}
