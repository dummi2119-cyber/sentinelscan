"""Transactional email delivery.

Uses the Resend API when RESEND_API_KEY is set. Without it, the message is
printed to the server log (dev fallback) so reset flows stay testable locally
and on first deploy before an email provider is wired up.
"""
import json
import os
import urllib.request

RESEND_URL = "https://api.resend.com/emails"
FROM_EMAIL = os.environ.get("FROM_EMAIL", "SentinelScan <admin@sentinel.local>")


def send_email(to: str, subject: str, html: str) -> bool:
    """Send an HTML email. Returns True on delivery, False otherwise."""
    api_key = os.environ.get("RESEND_API_KEY", "").strip()
    if not api_key:
        print(f"[SentinelScan][EMAIL] not delivered (no RESEND_API_KEY): to={to} subject={subject}", flush=True)
        print(f"[SentinelScan][EMAIL] body preview: {html[:200].strip()}", flush=True)
        return False
    payload = json.dumps({"from": FROM_EMAIL, "to": to, "subject": subject, "html": html}).encode("utf-8")
    req = urllib.request.Request(
        RESEND_URL,
        data=payload,
        method="POST",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status < 300
    except Exception as exc:  # network / API error — never crash the request
        print(f"[SentinelScan][EMAIL] send failed: {exc}", flush=True)
        return False
