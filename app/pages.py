"""Server-rendered page routes: marketing, auth, user panel, admin panel."""
import os

from fastapi import APIRouter, Request, Form, HTTPException, Query
from fastapi.responses import RedirectResponse, JSONResponse, FileResponse

from . import config, db, security, emailer
from .main import render, current_user, require_user, require_admin

router = APIRouter()


# ------------------------------------------------------------------ helpers
def _login_user(row):
    token = security.create_token(row["id"], row["role"])
    resp = RedirectResponse(url="/admin/dashboard" if row["role"] == "admin" else "/app/dashboard", status_code=302)
    resp.set_cookie(config.COOKIE_NAME, token, httponly=True, samesite="lax", max_age=config.TOKEN_TTL_SECONDS)
    return resp


def _email_ok(email):
    return "@" in email and "." in email.split("@")[-1] and len(email) < 120


# ------------------------------------------------------------------ public
@router.get("/")
def index(request: Request):
    plans = db.list_plans()
    tools = db.list_tools()
    return render(request, "index.html", {"plans": plans, "tools": tools, "active": "home"})


@router.get("/login")
def login_page(request: Request):
    if request.state.user and request.state.user.get("role") == "user":
        return RedirectResponse("/app/dashboard", status_code=302)
    return render(request, "auth/login.html", {"active": "login"})


@router.get("/register")
def register_page(request: Request):
    if request.state.user and request.state.user.get("role") == "user":
        return RedirectResponse("/app/dashboard", status_code=302)
    return render(request, "auth/register.html", {"active": "register"})


@router.post("/login")
async def login_submit(request: Request, email: str = Form(...), password: str = Form(...)):
    email = email.strip().lower()
    row = db.get_user_by_email(email)
    if not row or not security.verify_password(password, row["password_hash"], row["salt"]):
        return render(request, "auth/login.html", {"error": "Invalid email or password.", "email": email, "active": "login"})
    if not row["is_active"]:
        return render(request, "auth/login.html", {"error": "This account has been deactivated.", "email": email, "active": "login"})
    db.update_user_last_login(row["id"])
    return _login_user(row)


@router.post("/register")
async def register_submit(request: Request, name: str = Form(...), email: str = Form(...),
                          company: str = Form(""), password: str = Form(...), confirm: str = Form(...)):
    email = email.strip().lower()
    if not _email_ok(email):
        return render(request, "auth/register.html", {"error": "Enter a valid email address.", "name": name, "email": email, "active": "register"})
    if len(password) < 8:
        return render(request, "auth/register.html", {"error": "Password must be at least 8 characters.", "name": name, "email": email, "active": "register"})
    if password != confirm:
        return render(request, "auth/register.html", {"error": "Passwords do not match.", "name": name, "email": email, "active": "register"})
    if db.get_user_by_email(email):
        return render(request, "auth/register.html", {"error": "An account with that email already exists.", "name": name, "email": email, "active": "register"})
    pw_hash, salt = security.hash_password(password)
    plan = db.get_plan("free")
    with db.get_db() as conn:
        cur = conn.execute(
            "INSERT INTO users (email,password_hash,salt,name,company,role,plan,credits,is_active,created_at) VALUES (?,?,?,?,?,?,?,?,1,?)",
            (email, pw_hash, salt, name.strip(), company.strip(), "user", "free", plan["credits"] if plan else 10, db.now_ts()),
        )
        uid = cur.lastrowid
    db.audit("user_registered", email, actor="system")
    row = db.get_user(uid)
    return _login_user(row)


@router.get("/logout")
def logout(request: Request):
    resp = RedirectResponse(url="/", status_code=302)
    resp.delete_cookie(config.COOKIE_NAME)
    return resp


# ------------------------------------------------------------------ password reset (public)
@router.get("/forgot-password")
def forgot_password_page(request: Request):
    if request.state.user:
        return RedirectResponse("/app/dashboard", status_code=302)
    return render(request, "auth/forgot.html", {"active": "login"})


@router.post("/forgot-password")
async def forgot_password_submit(request: Request, email: str = Form(...)):
    email = email.strip().lower()
    # Respond identically whether or not the email exists (no account enumeration).
    row = db.get_user_by_email(email)
    if row and row["is_active"] and row["role"] != "admin":
        token = db.create_password_reset(row["id"])
        link = str(request.base_url).rstrip("/") + f"/reset-password?token={token}"
        html = (
            f"<p>You requested a password reset for <b>{email}</b>.</p>"
            f"<p><a href='{link}' style='display:inline-block;padding:10px 18px;background:#7c3aed;"
            f"color:#fff;text-decoration:none;border-radius:8px'>Reset password</a></p>"
            f"<p>This link expires in 1 hour. If you didn't request it, you can ignore this email.</p>"
        )
        emailer.send_email(email, "Reset your SentinelScan password", html)
    return render(request, "auth/forgot.html", {"sent": True, "email": email, "active": "login"})


@router.get("/reset-password")
def reset_password_page(request: Request, token: str = Query("")):
    if request.state.user:
        return RedirectResponse("/app/dashboard", status_code=302)
    valid = db.get_reset_by_token(token) is not None
    return render(request, "auth/reset.html", {"token": token, "valid": valid, "active": "login"})


@router.post("/reset-password")
async def reset_password_submit(request: Request, token: str = Form(...),
                                password: str = Form(...), confirm: str = Form(...)):
    info = db.get_reset_by_token(token)
    if not info:
        return render(request, "auth/reset.html", {"token": token, "valid": False, "active": "login",
                    "error": "This reset link is invalid or has expired. Please request a new one."})
    if len(password) < 8:
        return render(request, "auth/reset.html", {"token": token, "valid": True, "active": "login",
                    "error": "Password must be at least 8 characters."})
    if password != confirm:
        return render(request, "auth/reset.html", {"token": token, "valid": True, "active": "login",
                    "error": "Passwords do not match."})
    pw_hash, salt = security.hash_password(password)
    with db.get_db() as conn:
        conn.execute("UPDATE users SET password_hash=?, salt=? WHERE id=?", (pw_hash, salt, info["user_id"]))
    db.consume_reset_token(token)
    db.audit("password_reset", f"user:{info['user_id']}", actor=f"user:{info['user_id']}")
    return render(request, "auth/reset.html", {"token": token, "valid": True, "done": True, "active": "login"})


# ------------------------------------------------------------------ user panel
def _user_layout(request: Request, active: str, extra=None):
    u = require_user(request)
    ctx = {"active": active, "stats": db.user_stats(u["id"]), "me": u}
    if extra:
        ctx.update(extra)
    return render(request, f"user/{active}.html", ctx)


@router.get("/app")
def app_redirect():
    return RedirectResponse("/app/dashboard", status_code=302)


@router.get("/app/dashboard")
def user_dashboard(request: Request):
    require_user(request)
    return _user_layout(request, "dashboard", {"recent": db.scans_for_user(request.state.user["id"])[:8]})


@router.get("/app/new-scan")
def user_new_scan(request: Request):
    tools = [t for t in db.list_tools() if t["enabled"]]
    return _user_layout(request, "new_scan", {"tools": tools})


@router.get("/app/scans")
def user_scans(request: Request, tool: str = ""):
    require_user(request)
    scans = db.scans_for_user(request.state.user["id"])
    if tool:
        scans = [s for s in scans if s["tool"] == tool]
    return _user_layout(request, "scans", {"scans": scans, "tool_filter": tool})


@router.get("/app/scan/{scan_id}")
def user_scan_report(request: Request, scan_id: str):
    u = require_user(request)
    scan = db.get_scan(scan_id)
    if not scan or scan["user_id"] != u["id"]:
        raise RedirectResponse("/app/scans", status_code=302)
    findings = []
    if scan["report_json"] and os.path.exists(scan["report_json"]):
        import json as _json
        with open(scan["report_json"], encoding="utf-8") as fh:
            findings = _json.load(fh).get("findings", [])
    return _user_layout(request, "scan_report", {"scan": scan, "findings": findings})


@router.get("/app/profile")
def user_profile(request: Request):
    u = require_user(request)
    logs = [l for l in db.list_logs(200) if l.get("actor") == f"user:{u['id']}"]
    return _user_layout(request, "profile", {"logs": logs[:20], "plans": db.list_plans()})


@router.post("/app/profile/update")
async def user_profile_update(request: Request, name: str = Form(...), company: str = Form("")):
    u = require_user(request)
    with db.get_db() as conn:
        conn.execute("UPDATE users SET name=?, company=? WHERE id=?", (name.strip(), company.strip(), u["id"]))
    db.audit("profile_updated", f"user:{u['id']}", actor=f"user:{u['id']}")
    return RedirectResponse("/app/profile", status_code=302)


@router.post("/app/upgrade/{plan_key}")
async def user_upgrade(request: Request, plan_key: str):
    u = require_user(request)
    plan = db.get_plan(plan_key)
    if not plan:
        return RedirectResponse("/app/profile", status_code=302)
    with db.get_db() as conn:
        conn.execute("UPDATE users SET plan=?, credits=? WHERE id=?", (plan_key, int(plan["credits"]), u["id"]))
    db.audit(f"upgraded_to_{plan_key}", f"user:{u['id']}", actor=f"user:{u['id']}")
    return RedirectResponse("/app/profile", status_code=302)


@router.get("/app/password")
def user_change_password_page(request: Request):
    require_user(request)
    return _user_layout(request, "change_password")


@router.post("/app/password")
async def user_change_password_submit(request: Request, current: str = Form(...),
                                      password: str = Form(...), confirm: str = Form(...)):
    u = require_user(request)
    row = db.get_user(u["id"])
    if not security.verify_password(current, row["password_hash"], row["salt"]):
        return _user_layout(request, "change_password",
                            {"error": "Current password is incorrect.", "password": password, "confirm": confirm})
    if len(password) < 8:
        return _user_layout(request, "change_password",
                            {"error": "New password must be at least 8 characters.", "password": password, "confirm": confirm})
    if password != confirm:
        return _user_layout(request, "change_password",
                            {"error": "New passwords do not match.", "password": password, "confirm": confirm})
    pw_hash, salt = security.hash_password(password)
    with db.get_db() as conn:
        conn.execute("UPDATE users SET password_hash=?, salt=? WHERE id=?", (pw_hash, salt, u["id"]))
    # Log the user out of all sessions for safety after a password change.
    resp = RedirectResponse("/logout", status_code=302)
    resp.delete_cookie(config.COOKIE_NAME)
    db.audit("password_changed", f"user:{u['id']}", actor=f"user:{u['id']}")
    return resp


# ------------------------------------------------------------------ admin panel
def _admin_layout(request: Request, active: str, extra=None):
    a = require_admin(request)
    ctx = {"active": active, "admin": a, "stats": db.aggregate_stats()}
    if extra:
        ctx.update(extra)
    return render(request, f"admin/{active}.html", ctx)


@router.get("/admin")
def admin_redirect():
    return RedirectResponse("/admin/dashboard", status_code=302)


@router.get("/admin/login")
def admin_login_page(request: Request):
    return render(request, "auth/admin_login.html", {"active": "admin"})


@router.post("/admin/login")
async def admin_login_submit(request: Request, email: str = Form(...), password: str = Form(...)):
    email = email.strip().lower()
    row = db.get_user_by_email(email)
    if not row or row["role"] != "admin" or not security.verify_password(password, row["password_hash"], row["salt"]):
        return render(request, "auth/admin_login.html", {"error": "Invalid admin credentials.", "email": email, "active": "admin"})
    db.update_user_last_login(row["id"])
    db.audit("admin_login", email, admin_id=row["id"], actor=f"admin:{row['id']}")
    return _login_user(row)


@router.get("/admin/dashboard")
def admin_dashboard(request: Request):
    return _admin_layout(request, "dashboard")


@router.get("/admin/users")
def admin_users(request: Request):
    return _admin_layout(request, "users", {"users": db.list_users()})


@router.get("/admin/tools")
def admin_tools(request: Request):
    return _admin_layout(request, "tools", {"tools": db.list_tools(include_disabled=True)})


@router.get("/admin/scans")
def admin_scans(request: Request):
    return _admin_layout(request, "scans", {"scans": db.list_scans()})


@router.get("/admin/pricing")
def admin_pricing(request: Request):
    return _admin_layout(request, "pricing", {"plans": db.list_plans()})


@router.get("/admin/logs")
def admin_logs(request: Request):
    return _admin_layout(request, "logs", {"logs": db.list_logs()})


# ------------------------------------------------------------------ admin profile (self-service)
@router.get("/admin/profile")
def admin_profile(request: Request):
    a = require_admin(request)
    return _admin_layout(request, "profile", {"admin": a})


@router.post("/admin/profile")
async def admin_profile_submit(request: Request, current: str = Form(...),
                               password: str = Form(...), confirm: str = Form(...)):
    a = require_admin(request)
    row = db.get_user(a["id"])
    if not security.verify_password(current, row["password_hash"], row["salt"]):
        return _admin_layout(request, "profile",
                             {"admin": a, "error": "Current password is incorrect."})
    if len(password) < 8:
        return _admin_layout(request, "profile",
                             {"admin": a, "error": "New password must be at least 8 characters."})
    if password != confirm:
        return _admin_layout(request, "profile",
                             {"admin": a, "error": "New passwords do not match."})
    pw_hash, salt = security.hash_password(password)
    with db.get_db() as conn:
        conn.execute("UPDATE users SET password_hash=?, salt=? WHERE id=?", (pw_hash, salt, a["id"]))
    db.audit("admin_password_changed", f"admin:{a['id']}", actor=f"admin:{a['id']}")
    # After an admin changes their password, bounce them to admin login fresh for safety.
    return _admin_layout(request, "profile",
                         {"admin": a, "done": True,
                          "note": "Password updated. You can keep using this console, or log in again next time."})


@router.get("/admin/scan/{scan_id}/report")
def admin_scan_report(scan_id: str, request: Request):
    require_admin(request)
    scan = db.get_scan(scan_id)
    if not scan or not scan["report_html"] or scan["status"] != "completed":
        raise HTTPException(status_code=404, detail="Report not available")
    return FileResponse(scan["report_html"], media_type="text/html", filename=f"{scan_id}.html")
