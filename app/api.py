"""JSON API: scan lifecycle (user) and management actions (admin)."""
import json

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse, FileResponse

from . import config, db, security
from .main import require_user, require_admin
from . import runner

router = APIRouter()


# ============================================================ USER API
@router.get("/api/tools")
def api_tools():
    tools = []
    installed = None
    try:
        installed = {t["key"]: bool(t["enabled"]) for t in db.list_tools()}
    except Exception:
        pass
    for t in db.list_tools():
        tools.append({
            "key": t["key"], "name": t["name"], "category": t["category"],
            "description": t["description"], "credits": t["credits"],
        })
    return {"tools": tools}


@router.post("/api/scan")
async def api_create_scan(request: Request):
    u = require_user(request)
    body = await request.json()
    tool = (body.get("tool") or "").strip()
    target = (body.get("target") or "").strip()
    params = body.get("params") or {}

    tool_row = db.get_tool(tool)
    if not tool_row or not tool_row["enabled"]:
        return JSONResponse({"error": "Tool not available."}, status_code=400)
    if not target or len(target) > 300:
        return JSONResponse({"error": "Enter a valid target (URL, domain or IP)."}, status_code=400)

    # credit check
    cost = int(tool_row["credits"])
    if u["credits"] < cost:
        return JSONResponse({"error": "Insufficient credits. Upgrade your plan.", "need": cost, "have": u["credits"]}, status_code=402)

    # normalize target for the scanner
    params = {k: v for k, v in (params or {}).items() if isinstance(v, (str, int, float, bool))}
    sid = db.create_scan(u["id"], tool, target, params)
    runner.submit(sid)
    return {"ok": True, "scan_id": sid, "credits_remaining": max(u["credits"] - cost, 0), "status": "queued"}


@router.get("/api/scan/{scan_id}")
def api_scan_status(scan_id: str, request: Request):
    require_user(request)
    scan = db.get_scan(scan_id)
    if not scan:
        return JSONResponse({"error": "Scan not found."}, status_code=404)
    return _scan_public(scan)


@router.get("/api/scans")
def api_scans(request: Request):
    u = require_user(request)
    tool = request.query_params.get("tool", "")
    scans = db.scans_for_user(u["id"])
    if tool:
        scans = [s for s in scans if s["tool"] == tool]
    return {"scans": [_scan_public(s) for s in scans[:100]]}


@router.post("/api/scan/{scan_id}/cancel")
def api_scan_cancel(scan_id: str, request: Request):
    u = require_user(request)
    scan = db.get_scan(scan_id)
    if not scan or scan["user_id"] != u["id"]:
        return JSONResponse({"error": "Not found."}, status_code=404)
    ok = runner.cancel(scan_id)
    return {"ok": ok}


@router.get("/api/scan/{scan_id}/report.json")
def api_report_json(scan_id: str, request: Request):
    require_user(request)
    scan = db.get_scan(scan_id)
    if not scan or not scan["report_json"] or scan["status"] != "completed":
        if not scan:
            return JSONResponse({"error": "Not found."}, status_code=404)
        return JSONResponse({"error": "Report not ready."}, status_code=404)
    return FileResponse(scan["report_json"], media_type="application/json", filename=f"{scan_id}.json")


@router.get("/api/scan/{scan_id}/report.html")
def api_report_html(scan_id: str, request: Request):
    require_user(request)
    scan = db.get_scan(scan_id)
    if not scan or not scan["report_html"] or scan["status"] != "completed":
        if not scan:
            return JSONResponse({"error": "Not found."}, status_code=404)
        return JSONResponse({"error": "Report not ready."}, status_code=404)
    return FileResponse(scan["report_html"], media_type="text/html", filename=f"{scan_id}.html")


def _scan_public(scan):
    return {
        "id": scan["id"], "tool": scan["tool"], "target": scan["target"],
        "status": scan["status"], "error": scan["error"],
        "summary": json.loads(scan["summary"] or "{}"),
        "created_at": scan["created_at"], "started_at": scan["started_at"],
        "finished_at": scan["finished_at"],
        "created_h": db.to_dt(scan["created_at"]),
        "finished_h": db.to_dt(scan["finished_at"]),
    }


# ============================================================ ADMIN API
@router.get("/api/admin/stats")
def api_admin_stats(request: Request):
    require_admin(request)
    return db.aggregate_stats()


@router.get("/api/admin/scans")
def api_admin_scans(request: Request):
    require_admin(request)
    return {"scans": [_scan_public(s) for s in db.list_scans()[:200]]}


@router.post("/api/admin/users/{uid}/toggle")
def api_admin_toggle_user(uid: int, request: Request):
    a = require_admin(request)
    row = db.get_user(uid)
    if not row:
        return JSONResponse({"error": "User not found."}, status_code=404)
    new_state = 0 if row["is_active"] else 1
    with db.get_db() as conn:
        conn.execute("UPDATE users SET is_active=? WHERE id=?", (new_state, uid))
    db.audit("user_toggle_active" if new_state else "user_suspended",
             f"user:{uid} ({row['email']})", admin_id=a["id"], actor=f"admin:{a['id']}")
    return {"ok": True, "is_active": bool(new_state)}


@router.post("/api/admin/users/{uid}/plan")
async def api_admin_set_plan(uid: int, request: Request):
    a = require_admin(request)
    row = db.get_user(uid)
    if not row:
        return JSONResponse({"error": "User not found."}, status_code=404)
    body = await request.json()
    plan = (body.get("plan") or "").strip()
    credits = int(body.get("credits", 0))
    if plan not in ("free", "pro", "enterprise"):
        return JSONResponse({"error": "Invalid plan."}, status_code=400)
    with db.get_db() as conn:
        conn.execute("UPDATE users SET plan=?, credits=? WHERE id=?", (plan, credits, uid))
    db.audit("user_plan_changed", f"user:{uid} -> {plan}", admin_id=a["id"], actor=f"admin:{a['id']}")
    return {"ok": True, "plan": plan, "credits": credits}


@router.post("/api/admin/tools/{key}/toggle")
def api_admin_toggle_tool(key: str, request: Request):
    a = require_admin(request)
    t = db.get_tool(key)
    if not t:
        return JSONResponse({"error": "Tool not found."}, status_code=404)
    new_state = 0 if t["enabled"] else 1
    db.set_tool_enabled(key, bool(new_state))
    db.audit("tool_toggle" if new_state else "tool_disabled", key, admin_id=a["id"], actor=f"admin:{a['id']}")
    return {"ok": True, "enabled": bool(new_state)}


@router.post("/api/admin/pricing/{key}")
async def api_admin_update_plan(key: str, request: Request):
    a = require_admin(request)
    plan = db.get_plan(key)
    if not plan:
        return JSONResponse({"error": "Plan not found."}, status_code=404)
    body = await request.json()
    fields = {}
    if "name" in body:
        fields["name"] = str(body["name"])[:40]
    if "price" in body:
        fields["price"] = max(0, int(body["price"]))
    if "credits" in body:
        fields["credits"] = max(0, int(body["credits"]))
    if not fields:
        return JSONResponse({"error": "No fields to update."}, status_code=400)
    db.set_plan(key, **fields)
    db.audit("plan_updated", f"{key}: {fields}", admin_id=a["id"], actor=f"admin:{a['id']}")
    return {"ok": True, **fields}
