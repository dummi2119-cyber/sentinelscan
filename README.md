# SentinelScan

Automated security-scanning SaaS (FastAPI + Jinja2 + SQLite). Marketing site,
user panel, separate admin panel, and a scan engine that runs real tools
(Burp / ZAP / Nmap / Nikto / sqlmap / Subfinder / Nuclei) when installed and
falls back to a realistic simulation otherwise. CSRF-protected (signed
double-submit token).

## Local run

```bash
pip install -r requirements.txt
python run.py          # serves on http://localhost:8000
```

- User signup: `/register`
- Admin login: `/admin/login` → `admin@sentinel.local` / `Admin123!`
  (the admin account is re-seeded on every startup)

## Deploy (free)

The app reads `$PORT` and binds `0.0.0.0`, so it runs on any container/PaaS.

### Option A — Render (recommended, fastest, free subdomain)

1. Push this repo to GitHub (see below).
2. Go to https://render.com → **New +** → **Blueprint** → connect the repo.
   `render.yaml` auto-configures the web service.
3. Deploy. You get a live URL like `https://sentinelscan-xxxx.onrender.com`
   **for free** — no domain purchase needed.

> Free web services spin down after ~15 min idle (slow first request on wake).
> The SQLite DB lives on the ephemeral filesystem, so user accounts reset on
> restart; the admin account is always re-seeded. For a persistent DB, use a
> Fly.io volume or switch the `db` layer to Postgres.

### Option B — Fly.io (free tier, supports persistent volumes)

```bash
fly launch            # follows prompts, uses Dockerfile
fly secrets set PYTHON_VERSION=3.12
fly deploy
```

### Option C — PythonAnywhere (free tier)

Upload the repo, create a **Manual FastAPI/WSGI** web app, set the working
directory and module `app.main:app`. Free subdomain: `yourname.pythonanywhere.com`.

## Domains — what's actually free?

A real top-level domain (`.com`, `.io`, `.net`) is essentially **never free
long-term**. Realistic options:

- **Free subdomain from the host (zero cost, works today):**
  `*.onrender.com` (Render), `*.fly.dev` (Fly.io), `*.koyeb.app` (Koyeb),
  `*.pythonanywhere.com`. Use one of these — it's the genuinely free path.
- **Free for students:** GitHub Student Developer Pack gives ~1 year of a real
  domain (`.com` via Namecheap, `.me` via Name.com) — https://education.github.com/pack
- **Cheapest real domain (not free, ~$8–10/yr):** Cloudflare Registrar
  (at cost, no markup), Porkbun, or Namecheap. Then point its DNS `A`/`CNAME`
  at your host and add the custom domain in the host dashboard.

Avoid Freenom (`.tk/.ml/.ga`) — it has stopped accepting new registrations.

## Project layout

```
app/
  main.py      FastAPI app, auth middleware, CSRF middleware, template render
  csrf.py      signed double-submit CSRF token + validation
  pages.py     server-rendered pages (marketing, auth, user + admin panels)
  api.py       JSON API (scan lifecycle + admin actions)
  runner.py    background scan execution + HTML/JSON report generation
  scanners.py  scanner adapters (real tools + deterministic simulation)
  db.py        SQLite data layer + seeding
  security.py  PBKDF2 password hashing + JWT session tokens
  config.py    paths, secret, constants
run.py         launcher (respects $PORT)
```
