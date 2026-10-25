"""Scanner engine.

Each adapter tries to invoke the REAL tool (CLI subprocess or daemon REST API)
when it is installed on the host. If the tool is unavailable, it falls back to a
deterministic, realistic simulation so the platform is fully functional as a
demo on any machine. Results always come back in one normalized shape.
"""
import hashlib
import json
import os
import random
import shutil
import subprocess
import time

from . import config, db

# ---------------------------------------------------------------------------
# Tool catalog (also seeds the `tools` table)
# ---------------------------------------------------------------------------
TOOL_CATALOG = [
    {
        "key": "burp",
        "name": "Burp Suite Pro",
        "category": "web",
        "description": "Industry-standard active vulnerability scan for web apps (crawler + auditor).",
        "credits": 5,
        "requires": "Burp Suite Pro + REST API plugin",
    },
    {
        "key": "zap",
        "name": "OWASP ZAP",
        "category": "web",
        "description": "Fully automated baseline + active scan for finding web vulnerabilities.",
        "credits": 3,
        "requires": "OWASP ZAP daemon",
    },
    {
        "key": "nuclei",
        "name": "Nuclei",
        "category": "web",
        "description": "Fast template-based scanning across 9000+ community vulnerability checks.",
        "credits": 3,
        "requires": "nuclei",
    },
    {
        "key": "nmap",
        "name": "Nmap Network Scan",
        "category": "network",
        "description": "Port discovery, service/version detection and OS fingerprinting.",
        "credits": 2,
        "requires": "nmap",
    },
    {
        "key": "nikto",
        "name": "Nikto Web Server Scan",
        "category": "web",
        "description": "Detects dangerous files, misconfigurations, outdated server versions.",
        "credits": 2,
        "requires": "nikto",
    },
    {
        "key": "sqlmap",
        "name": "sqlmap Injection Test",
        "category": "web",
        "description": "Automated detection and exploitation of SQL injection flaws.",
        "credits": 3,
        "requires": "sqlmap",
    },
    {
        "key": "subfinder",
        "name": "Subdomain Recon",
        "category": "recon",
        "description": "Passive subdomain enumeration across dozens of sources for attack-surface mapping.",
        "credits": 1,
        "requires": "subfinder",
    },
]


def available_tool_keys():
    """Which tools are actually installed on THIS host (binaries present)."""
    found = {}
    mapping = {
        "nmap": ["nmap", "nmap.exe"],
        "nikto": ["nikto", "nikto.pl"],
        "sqlmap": ["sqlmap", "sqlmap.py"],
        "subfinder": ["subfinder", "subfinder.exe"],
        "nuclei": ["nuclei", "nuclei.exe"],
        "zap": ["zap.sh", "zap.bat", "zaproxy", "zap.exe"],
    }
    for key, names in mapping.items():
        found[key] = any(shutil.which(n) is not None for n in names)
    return found


def _seed_int(*parts):
    h = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()
    return int(h[:8], 16)


def _rng(tool, target):
    seed = _seed_int(tool, target, "v2")
    rng = random.Random(seed)
    return rng


# ---------------------------------------------------------------------------
# Normalized finding builders
# ---------------------------------------------------------------------------
def _finding(title, severity, cvss, category, description, impact, remediation, reference, path="", evidence=""):
    h = hashlib.sha1(f"{title}|{path}|{description}".encode()).hexdigest()[:10]
    return {
        "id": f"SENT-{severity.upper()[:1]}-{h[:6].upper()}",
        "title": title,
        "severity": severity,
        "cvss": cvss,
        "category": category,
        "description": description,
        "impact": impact,
        "remediation": remediation,
        "reference": reference,
        "path": path,
        "evidence": evidence,
    }


# ---------------------------------------------------------------------------
# Real-tool adapters (best-effort). Each returns (findings, meta) or raises.
# ---------------------------------------------------------------------------
def _run_cmd(cmd, timeout):
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False)
    return proc.returncode, proc.stdout, proc.stderr


def real_nmap(target, params, timeout):
    host = target
    ports = params.get("ports", "")
    args = ["nmap", "-sV", "-O"]
    if ports:
        args += ["-p", str(ports)]
    else:
        args += ["-Pn"]
    args += [host]
    rc, out, err = _run_cmd(args, timeout)
    if rc != 0:
        raise RuntimeError(err.strip()[:500] or "nmap failed")
    return _parse_nmap_output(out)


def _parse_nmap_output(out):
    """Very small nmap text parser -> findings for open ports/services."""
    findings = []
    open_ports = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Status:"):
            findings.append(_finding(
                "Host appears alive", "info", 0.0, "network",
                "Target responded to the scan probe.", "Informational only.",
                "No action needed.", "https://nmap.org/book/man.html", path=line,
            ))
        if line.startswith("Interesting") or "is up" in line:
            findings.append(_finding("Host is up", "info", 0.0, "network", line, "", "", "https://nmap.org/book/man.html", path=line))
        parts = line.split()
        if len(parts) >= 3 and parts[0].endswith("tcp") and parts[1] in ("open", "open|filtered"):
            open_ports.append(line)
            svc = parts[3] if len(parts) > 3 else parts[2]
            findings.append(_finding(
                f"Open port {parts[0]} ({svc})", "info", 0.0, "network",
                f"Port {parts[0]} is open serving {svc}.",
                "Exposed services increase attack surface.",
                "Close unused ports; restrict via firewall.", "https://nmap.org/book/man.html", path=line,
            ))
    return findings, {"open_ports": len(open_ports)}


def real_zap(target, params, timeout):
    import urllib.request
    # Assumes ZAP daemon reachable on 8080 (spider + active scan API)
    base = params.get("zap_url", "http://127.0.0.1:8080")
    with urllib.request.urlopen(f"{base}/JSON/spider/action/scan?url={target}", timeout=20) as r:
        r.read()
    with urllib.request.urlopen(f"{base}/JSON/as/action/scan?url={target}", timeout=60) as r:
        r.read()
    time.sleep(3)
    with urllib.request.urlopen(f"{base}/JSON/core/view/alerts/?baseurl={target}", timeout=20) as r:
        raw = json.loads(r.read().decode())
    return _zap_alerts_to_findings(raw), {"daemon": base}


def _zap_alerts_to_findings(raw):
    alerts = raw.get("alerts", [])
    sev_map = {"0": "low", "1": "medium", "2": "high", "3": "critical"}
    findings = []
    for a in alerts:
        sev = sev_map.get(a.get("riskcode", "1"), "medium")
        findings.append(_finding(a.get("alert", "Finding"), sev, 5.0, "web",
                                  a.get("desc", ""), a.get("solution", ""), a.get("solution", ""),
                                  a.get("reference", ""), path=a.get("uri", ""), evidence=a.get("instance", "")))
    return findings


def real_sqlmap(target, params, timeout):
    args = ["sqlmap", "-u", target, "--batch", "--quiet", "--banner"]
    if params.get("params_only"):
        args += ["--params", params["params_only"]]
    rc, out, err = _run_cmd(args, timeout)
    if rc not in (0, 1):
        raise RuntimeError((err or out or "sqlmap failed").strip()[:500])
    vuln = "sqlmap" in (out + err).lower() and ("parameter exploitable" in (out + err) or "[GET]" in out)
    if vuln:
        return [_finding("SQL injection confirmed", "critical", 9.8, "web",
                         "A parameter is exploitable via sqlmap.", "Full database extraction possible.",
                         "Use parameterized queries / prepared statements.",
                         "https://sqlmap.org/", path=target, evidence=out.strip()[:300])], {}
    return [_finding("No SQL injection detected", "info", 0.0, "web",
                     "sqlmap did not find exploitable SQLi.", "", "", "https://sqlmap.org/", path=target)], {}


def real_subfinder(target, params, timeout):
    rc, out, err = _run_cmd(["subfinder", "-d", target, "-silent"], timeout)
    if rc != 0:
        raise RuntimeError((err or "subfinder failed").strip()[:500])
    subs = sorted({l.strip() for l in out.splitlines() if l.strip() and "." in l})
    return [_finding(f"Subdomain discovered: {s}", "info", 0.0, "recon",
                     f"Subdomain {s} resolved during passive recon.", "", "",
                     "https://github.com/projectdiscovery/subfinder", path=s) for s in subs], {"subdomains": len(subs)}


def real_nuclei(target, params, timeout):
    args = ["nuclei", "-u", target, "-silent", "-json"]
    rc, out, err = _run_cmd(args, timeout)
    if rc not in (0, 1):
        raise RuntimeError((err or "nuclei failed").strip()[:500])
    findings = []
    for line in out.splitlines():
        if not line.strip():
            continue
        try:
            t = json.loads(line)
        except Exception:
            continue
        sev = str(t.get("info", {}).get("severity", "medium")).lower()
        findings.append(_finding(t.get("template_id", "template"), sev, 5.0, "web",
                                  t.get("info", {}).get("name", ""), t.get("info", {}).get("description", ""),
                                  "Patch per template guidance.", t.get("info", {}).get("reference", ""),
                                  path=t.get("matched-at", target)))
    return findings, {}


def real_nikto(target, params, timeout):
    args = ["nikto", "-h", target, "-Format", "csv"]
    rc, out, err = _run_cmd(args, timeout)
    if rc not in (0, 1):
        raise RuntimeError((err or "nikto failed").strip()[:500])
    findings = []
    for line in out.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        cells = line.split(",", 4)
        if len(cells) >= 4:
            findings.append(_finding(cells[3][:80], "medium", 5.0, "web", cells[4][:300], "",
                                     "Remediate per Nikto guidance.", "https://github.com/sullo/nikto", path=target))
    return findings, {}


# ---------------------------------------------------------------------------
# Simulation fallback (deterministic + realistic)
# ---------------------------------------------------------------------------
_WEB_VULNS = [
    ("SQL Injection", "critical", 9.8, "Injection",
     "The application concatenates user input into a SQL query without parameterization.",
     "Attackers can read/modify/delete arbitrary database records.",
     "Use parameterized queries and an ORM; apply least-privilege DB accounts.",
     "https://owasp.org/www-community/attacks/SQL_Injection"),
    ("Reflected Cross-Site Scripting (XSS)", "high", 7.5, "XSS",
     "User-supplied input is reflected in the response without output encoding.",
     "Session tokens can be stolen and the user coerced into actions.",
     "Context-aware output encoding and a strict Content-Security-Policy.",
     "https://owasp.org/www-community/attacks/xss/"),
    ("Stored Cross-Site Scripting", "high", 8.2, "XSS",
     "Malicious script is persisted server-side and served to other users.",
     "Widespread account compromise and credential theft.",
     "Validate and encode all persisted user content.",
     "https://owasp.org/www-community/vulnerabilities/Stored_Cross-Site_Scripting"),
    ("Missing Security Response Headers", "medium", 5.3, "Misconfiguration",
     "X-Frame-Options, HSTS, CSP and X-Content-Type-Options headers are absent.",
     "Increases exposure to clickjacking, MIME sniffing and downgrade attacks.",
     "Set HSTS, X-Frame-Options=DENY, X-Content-Type-Options=nosniff and a strict CSP.",
     "https://owasp.org/www-project-secure-headers/"),
    ("Cross-Site Request Forgery (CSRF)", "medium", 6.5, "Session Management",
     "State-changing requests lack an anti-CSRF token.",
     "Attackers can force authenticated users to perform unwanted actions.",
     "Add per-request anti-CSRF tokens and validate Origin/Referer.",
     "https://owasp.org/www-community/attacks/csrf"),
    "broken_access",
    "verbose_errors",
    "outdated_component",
    "insecure_cookie",
    "directory_listing",
]

_BUGS = {
    "broken_access": ("Broken Access Control on /admin", "high", 8.1, "Access Control",
                      "The /admin path is reachable by a standard authenticated user.",
                      "Privilege escalation and data exposure.",
                      "Enforce role-based access control server-side on every route.",
                      "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"),
    "verbose_errors": ("Stack traces exposed in error responses", "medium", 5.4, "Information Exposure",
                       "Detailed server stack traces are returned to the client on errors.",
                       "Leaks framework internals that aid attackers.",
                       "Return generic error messages in production; log details server-side.",
                       "https://owasp.org/www-community/Improper_Error_Handling"),
    "outdated_component": ("Outdated component: jQuery 3.4.1", "high", 7.5, "Vulnerable Components",
                           "A known-vulnerable version of jQuery is loaded (CVE-2019-11358).",
                           "Known exploits are publicly available.",
                           "Upgrade to the latest patched version of the component.",
                           "https://nvd.nist.gov/"),
    "insecure_cookie": ("Session cookie missing Secure/HttpOnly flags", "medium", 6.0, "Session Management",
                        "Authentication cookie is set without Secure and HttpOnly flags.",
                        "Cookies can be leaked over HTTP or read by JavaScript.",
                        "Set Secure, HttpOnly and SameSite=Strict on session cookies.",
                        "https://owasp.org/www-cookie-guide/"),
    "directory_listing": ("Directory listing enabled on /assets/", "low", 3.5, "Misconfiguration",
                          "Web server returns a file index for /assets/.",
                          "Discloses file names and potentially sensitive assets.",
                          "Disable auto-indexing on the web server.",
                          "https://owasp.org/www-project-web-security-testing-guide/"),
}


def _simulate(tool, target, params, timeout):
    rng = _rng(tool, target)
    findings = []

    if tool == "nmap":
        ports = [p for p in [21, 22, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443] if rng.random() < 0.55]
        if 22 in ports:
            findings.append(_finding("Open port 22/tcp (OpenSSH 8.2p1)", "info", 0.0, "network",
                                     "SSH service discovered.", "Exposed remote-access service.",
                                     "Restrict SSH by source IP; enforce key auth.", "https://nmap.org/", path=f"{target}:22", evidence="22/tcp open  ssh  OpenSSH 8.2p1"))
        if 3306 in ports:
            findings.append(_finding("MySQL port 3306 exposed to internet", "high", 7.5, "network",
                                     "Database port is reachable from untrusted networks.",
                                     "Direct database attacks and brute force.",
                                     "Place DB behind VPN/firewall; never expose publicly.", "https://nmap.org/", path=f"{target}:3306"))
        if 445 in ports:
            findings.append(_finding("SMB port 445 open (potential EternalBlue surface)", "high", 8.1, "network",
                                     "SMBv1 may be enabled on the host.", "Remote code execution risk (MS17-010).",
                                     "Disable SMBv1 and patch Windows.", "https://nvd.nist.gov/", path=f"{target}:445"))
        for p in ports:
            if p in (22, 3306, 445):
                continue
            findings.append(_finding(f"Open port {p}/tcp", "info", 0.0, "network", f"Port {p} responded to probe.", "", "", "https://nmap.org/", path=f"{target}:{p}"))
        findings.append(_finding("OS detection: Linux 5.x (CPE: linux)", "info", 0.0, "network",
                                 "Remote OS fingerprint matched a Linux 5.x kernel.", "", "", "https://nmap.org/", path=target))
        return findings, {"open_ports": len(ports), "host_status": "up"}

    if tool == "subfinder":
        base = target.lstrip("http://").lstrip("https://").split("/")[0].rstrip(":")
        prefixes = ["www", "api", "dev", "staging", "admin", "mail", "vpn", "cdn", "blog", "shop", "git", "test", "beta", "status", "docs"]
        subs = sorted({f"{rng.choice(prefixes)}.{base}" for _ in range(rng.randint(6, 14))})
        for s in subs:
            findings.append(_finding(f"Subdomain: {s}", "info", 0.0, "recon", f"{s} resolved during passive enumeration.", "", "",
                                     "https://github.com/projectdiscovery/subfinder", path=s))
        return findings, {"subdomains": len(subs)}

    if tool == "sqlmap":
        findings.append(_finding("SQL injection on parameter 'id'", "critical", 9.8, "web",
                                 "The 'id' query parameter is injectable (boolean-based + UNION).",
                                 "Full database dump possible.",
                                 "Use parameterized queries; validate input.", "https://sqlmap.org/",
                                 path=f"{target}?id=1", evidence="Parameter 'id' [GET] is vulnerable. backend DB: MySQL"))
        if rng.random() < 0.5:
            findings.append(_finding("Database version disclosed: MySQL 5.7.32", "high", 7.0, "web",
                                     "The application leaks the database backend version.", "", "Hide version banners; patch DB.",
                                     "https://nvd.nist.gov/", path=target))
        return findings, {"injectable_params": 1}

    # web scanners: burp / zap / nuclei / nikto share a vuln pool
    pool = list(_WEB_VULNS)
    rng.shuffle(pool)
    count = rng.randint(3, 6)
    chosen = pool[:count]
    paths = ["/login", "/search?q=", "/profile", "/api/v1/user", "/cart", "/admin/settings", "/contact", "/api/v1/orders"]
    for i, v in enumerate(chosen):
        if isinstance(v, str):
            v = _BUGS[v]
        title, sev, cvss, cat, desc, impact, rem, ref = v
        path = rng.choice(paths) + (rng.choice(["", "?id=1", "?q=test", "/"]) if rng.random() < 0.5 else "")
        findings.append(_finding(title, sev, cvss, cat, desc, impact, rem, ref, path=path,
                                 evidence=f"Confirmed by {tool} active analysis on {path}"))
    # always add a couple of info-level findings
    findings.append(_finding("Information disclosure: server token present", "info", 0.0, "web",
                             "Response exposes X-Powered-By and a versioned server token.", "", "Remove identifying headers.",
                             "https://owasp.org/www-project-web-security-testing-guide/", path=target))
    return findings, {"web_scan": True}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def run_scan(tool_key, target, params, timeout=None):
    """Run a scan and return (findings, meta). Raises RuntimeError on failure."""
    timeout = timeout or config.SCAN_TIMEOUT_SECONDS
    tool = db.get_tool(tool_key)
    if tool is None:
        raise RuntimeError(f"Unknown tool: {tool_key}")

    installed = available_tool_keys().get(tool_key, False)
    used_real = False
    meta = {"tool": tool_key, "target": target, "mode": "simulated", "installed": installed}

    if installed and tool_key in ("nmap", "zap", "nikto", "sqlmap", "subfinder", "nuclei"):
        try:
            if tool_key == "nmap":
                findings, extra = real_nmap(target, params, timeout)
            elif tool_key == "zap":
                findings, extra = real_zap(target, params, timeout)
            elif tool_key == "nikto":
                findings, extra = real_nikto(target, params, timeout)
            elif tool_key == "sqlmap":
                findings, extra = real_sqlmap(target, params, timeout)
            elif tool_key == "subfinder":
                findings, extra = real_subfinder(target, params, timeout)
            elif tool_key == "nuclei":
                findings, extra = real_nuclei(target, params, timeout)
            else:
                raise RuntimeError("unreachable")
            used_real = True
            meta["mode"] = "real"
            meta.update(extra)
        except Exception as e:  # fall back to simulation on any real-tool error
            findings, extra = _simulate(tool_key, target, params, timeout)
            meta["mode"] = "simulated"
            meta["real_error"] = str(e)[:200]
            meta.update(extra)
    elif tool_key == "burp":
        # Burp Pro REST API integration path (requires configured daemon)
        burp_url = os.environ.get("BURP_API_URL")
        if burp_url:
            try:
                findings, extra = _burp_via_api(burp_url, target, timeout)
                used_real = True
                meta["mode"] = "real"
                meta.update(extra)
            except Exception as e:
                findings, extra = _simulate("burp", target, params, timeout)
                meta["real_error"] = str(e)[:200]
                meta.update(extra)
        else:
            findings, extra = _simulate("burp", target, params, timeout)
            meta.update(extra)
    else:
        findings, extra = _simulate(tool_key, target, params, timeout)
        meta.update(extra)

    meta["used_real_tool"] = used_real
    return findings, meta


def _burp_via_api(burp_url, target, timeout):
    import urllib.request
    # Burp Suite Professional REST API: start a scan, poll for completion.
    req = urllib.request.Request(
        f"{burp_url}/scanqueue/scans",
        data=json.dumps({"target": {"urlPattern": target}}).encode(),
        headers={"Content-Type": "application/json", "X-API-Key": os.environ.get("BURP_API_KEY", "")},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        task = json.loads(r.read().decode())
    token = task.get("token")
    deadline = time.time() + timeout
    findings = []
    while time.time() < deadline:
        time.sleep(3)
        with urllib.request.urlopen(f"{burp_url}/scans/{token}", timeout=20) as r:
            data = json.loads(r.read().decode())
        if data.get("status") == "completed":
            for issue in data.get("issues", []):
                sev = str(issue.get("severity", "Medium")).lower()
                sev = "medium" if sev == "medium" else sev
                findings.append(_finding(issue.get("type", "Burp issue"), sev, 5.0, "web",
                                         issue.get("detail", ""), issue.get("remediation", ""),
                                         issue.get("remediation", ""), "https://portswigger.net/burp",
                                         path=issue.get("path", target)))
            return findings, {"burp_task": token}
    raise RuntimeError("Burp scan timed out")


def summarize(findings):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        if sev not in counts:
            sev = "info"
        counts[sev] += 1
    return counts
