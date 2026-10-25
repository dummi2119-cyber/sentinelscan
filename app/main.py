"""FastAPI application: middleware, auth deps, template wiring, static."""
import os

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import config, db, security, csrf

app = FastAPI(title="SentinelScan", version="1.0.0")

templates = Jinja2Templates(directory=config.TEMPLATE_DIR)
templates.env.filters["dt"] = db.to_dt
app.mount("/static", StaticFiles(directory=config.STATIC_DIR), name="static")

# Ensure schema + seed exist regardless of launcher (uvicorn, gunicorn, test client).
db.init_db()


@app.on_event("startup")
def _startup():
    db.init_db()


# ---- request-scoped auth -------------------------------------------------
@app.middleware("http")
async def _auth_context(request: Request, call_next):
    token = request.cookies.get(config.COOKIE_NAME)
    request.state.user = None
    if token:
        info = security.token_user(token)
        if info:
            row = db.get_user(info["id"])
            if row and row["is_active"]:
                request.state.user = {
                    "id": row["id"], "email": row["email"], "name": row["name"],
                    "role": row["role"], "plan": row["plan"], "company": row["company"],
                    "credits": row["credits"],
                }
            elif row and not row["is_active"]:
                # inactive -> treat as logged out
                request.state.user = {"blocked": True, "id": row["id"]}

    # CSRF: reuse an existing valid token, else mint one; expose it to templates
    # and set it as a (non-HttpOnly, SameSite=Lax) cookie for double-submit.
    ctoken = request.cookies.get(csrf.COOKIE_NAME)
    if not ctoken or not csrf.valid_token(ctoken):
        ctoken = csrf.generate_token()
    request.state.csrf_token = ctoken

    resp = await call_next(request)
    resp.set_cookie(
        csrf.COOKIE_NAME, ctoken, httponly=False, samesite="lax",
        max_age=csrf._MAX_AGE, path="/",
    )
    return resp


def current_user(request: Request):
    return request.state.user


def require_user(request: Request):
    u = request.state.user
    if not u or u.get("blocked"):
        raise HTTPException(status_code=401, detail="Authentication required")
    if u.get("role") != "user":
        # admins hitting user routes -> bounce to admin area
        raise HTTPException(status_code=403, detail="Forbidden")
    return u


def require_admin(request: Request):
    u = request.state.user
    if not u or u.get("blocked"):
        raise HTTPException(status_code=401, detail="Authentication required")
    if u.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return u


# ---- helpers for templates ----------------------------------------------
def render(request: Request, name: str, ctx: dict | None = None):
    ctx = dict(ctx or {})
    u = request.state.user
    ctx["current_user"] = None if not u else (None if u.get("blocked") else u)
    ctx["is_admin"] = bool(u and u.get("role") == "admin")
    ctx["is_user"] = bool(u and u.get("role") == "user")
    ctx["tagline"] = db.get_setting("tagline", "Automated security scanning for modern teams")
    ctx["csrf"] = getattr(request.state, "csrf_token", None)
    return templates.TemplateResponse(request, name, ctx)


# ---- global handlers -----------------------------------------------------
@app.exception_handler(404)
async def _nf(request: Request, exc):
    if request.url.path.startswith(("/static", "/api")):
        return JSONResponse({"detail": "not found"}, status_code=404)
    return templates.TemplateResponse(
        request, "errors/404.html", {"current_user": request.state.user,
                                     "is_admin": False, "is_user": False, "tagline": ""}, status_code=404)


@app.get("/health")
def health():
    return {"status": "ok", "app": "SentinelScan"}


def include(routers):
    for r in routers:
        app.include_router(r)


# ---- CSRF validation (raw ASGI middleware, outermost) --------------------
class CSRFMiddleware:
    """Reject state-changing requests whose CSRF token doesn't match the cookie.

    Reads and re-injects the request body so endpoint handlers (Form/JSON)
    still receive it untouched. Registered last so it sits outermost and
    consumes the body before any BaseHTTPMiddleware does.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in ("POST", "PUT", "PATCH"):
            return await self.app(scope, receive, send)

        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body", False):
                break

        if not csrf.check(scope, body):
            payload = b'{"detail":"CSRF token invalid"}'
            await send({"type": "http.response.start", "status": 403,
                        "headers": [(b"content-type", b"application/json; charset=utf-8")],
                        "content-length": str(len(payload)).encode()})
            await send({"type": "http.response.body", "body": payload})
            return

        async def receive_again():
            return {"type": "http.request", "body": body, "more_body": False}

        return await self.app(scope, receive_again, send)


# Registering last makes this the outermost middleware (runs first on request).
app.add_middleware(CSRFMiddleware)
