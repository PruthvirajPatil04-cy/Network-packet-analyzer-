"""
Simulated College Student Portal & Live Demo Server (student.college.edu).
Demonstrates real-time defensive application-layer firewalling, honeypot telemetry,
and dynamic threat blocking.
"""

from __future__ import annotations
import os
import time
import json
import asyncio
import logging
from typing import Optional, Dict, Any, List
from collections import deque
from contextlib import asynccontextmanager

from fastapi import (
    FastAPI, Request, Response, Form, Depends, HTTPException,
    status, Cookie
)
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
import httpx

from demo_server.blocklist import blocklist
from demo_server.threat_engine import threat_engine

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [demo-server] %(message)s"
)
logger = logging.getLogger("demo-server")

BOOT_TIME = time.time()
BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8000")
DEMO_CREDENTIALS = {
    "username": os.environ.get("STUDENT_USER", "student"),
    "password": os.environ.get("STUDENT_PASS", "college2026"),
}
ADMIN_SECRET = os.environ.get("ADMIN_SECRET_TOKEN", "super-secret-admin-token-2026")

# In-memory sliding history of events (last 500 decisions)
_recent_events: deque[Dict[str, Any]] = deque(maxlen=500)
_stats_lock = asyncio.Lock()
_packets_seen_count = 0
_http_client: Optional[httpx.AsyncClient] = None

# Optional Redis connection
_redis_client = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _http_client, _redis_client
    logger.info("Initializing Student Portal Demo Server (student.college.edu)...")
    _http_client = httpx.AsyncClient(timeout=3.0)

    redis_url = os.environ.get("REDIS_URL", None)
    if redis_url:
        try:
            import redis.asyncio as aioredis
            _redis_client = aioredis.from_url(redis_url, decode_responses=True)
            await _redis_client.ping()
            logger.info(f"Connected to Redis at {redis_url} for event publishing")
        except Exception as e:
            logger.warning(f"Redis unavailable ({e}), running in-memory event mode")
            _redis_client = None

    yield

    if _http_client:
        await _http_client.aclose()
    if _redis_client:
        await _redis_client.close()
    logger.info("Demo server stopped.")


app = FastAPI(
    title="College Student Portal (student.college.edu)",
    version="1.0.0",
    docs_url="/api/docs",
    lifespan=lifespan,
)


async def emit_decision_event(event: Dict[str, Any]) -> None:
    """Publish event to in-memory deque, Redis stream, and backend server."""
    global _packets_seen_count
    _packets_seen_count += 1

    async with _stats_lock:
        _recent_events.append(event)

    # Publish to Redis Stream
    if _redis_client:
        try:
            await _redis_client.xadd(
                "demo_server_events",
                {"event": json.dumps(event)},
                maxlen=5000,
            )
        except Exception:
            pass

    # Post event asynchronously to backend API (fire and forget)
    if _http_client and BACKEND_URL:
        try:
            asyncio.create_task(
                _http_client.post(
                    f"{BACKEND_URL}/api/server/event-ingest",
                    json=event,
                    headers={"X-API-Key": "packet-analyzer-secret-key-2026"},
                )
            )
        except Exception:
            pass


# --- Application Layer Threat Defense Middleware ---

@app.middleware("http")
async def security_firewall_middleware(request: Request, call_next):
    path = request.url.path
    # Exclude internal healthcheck, docs, and sync APIs from polluting the student traffic feed
    if path in ("/health", "/favicon.ico", "/api/blocked", "/api/events", "/api/block", "/api/docs", "/openapi.json") or path.startswith("/api/blocked/"):
        return await call_next(request)

    ts = time.time()
    raw_ip = request.headers.get("x-forwarded-for") or (
        request.client.host if request.client else "127.0.0.1"
    )
    src_ip = raw_ip.split(",")[0].strip() if "," in raw_ip else raw_ip.strip()
    request.state.client_ip = src_ip

    method = request.method
    dest_host = request.headers.get("host", "student.college.edu")
    query_str = request.url.query
    user_agent = request.headers.get("user-agent", "")
    admin_token = request.headers.get("x-admin-token") or request.query_params.get("token")

    # Read body safely for inspection and cache in request.state.body
    body_bytes = await request.body()
    request.state.body = body_bytes
    body_str = body_bytes.decode("utf-8", errors="replace")
    bytes_in = len(body_bytes)

    # 1. FAST-PATH: Check if IP is already blocked
    is_blocked, block_entry = blocklist.is_blocked(src_ip)
    if is_blocked and block_entry:
        event = {
            "ts": ts,
            "src_ip": src_ip,
            "dst": dest_host,
            "path": path,
            "method": method,
            "status": 403,
            "decision": "block",
            "score": block_entry.score,
            "reasons": [f"Source IP previously blocked: {block_entry.reason}"],
            "severity": "CRITICAL",
            "user_agent": user_agent,
            "bytes_in": bytes_in,
            "bytes_out": 85,
        }
        await emit_decision_event(event)
        return JSONResponse(
            status_code=403,
            content={
                "detail": "blocked",
                "error": "Access Denied by Application Firewall",
                "ip": src_ip,
                "reason": block_entry.reason,
                "ttl_remaining_seconds": max(0, int(block_entry.expires_at - time.time())),
            },
            headers={"X-Blocked-By": "ThreatEngine-v2"},
        )

    # 2. RUN THREAT ENGINE ANALYSIS
    decision, score, reasons, severity = threat_engine.evaluate_request(
        src_ip=src_ip,
        path=path,
        method=method,
        headers=dict(request.headers),
        body_str=body_str,
        query_str=query_str,
        dest_port=request.url.port or 8001,
        admin_token=admin_token,
    )

    # 3. ACT ON DECISION
    if decision == "block":
        # Add to blocklist
        reason_text = "; ".join(reasons) if reasons else "Security rule violation"
        block_entry = blocklist.block_ip(src_ip, reason_text, score)

        event = {
            "ts": ts,
            "src_ip": src_ip,
            "dst": dest_host,
            "path": path,
            "method": method,
            "status": 403,
            "decision": "block",
            "score": score,
            "reasons": reasons,
            "severity": severity,
            "user_agent": user_agent,
            "bytes_in": bytes_in,
            "bytes_out": 120,
        }
        await emit_decision_event(event)

        return JSONResponse(
            status_code=403,
            content={
                "detail": "blocked",
                "error": "Forbidden - Malicious Activity Detected",
                "ip": src_ip,
                "reasons": reasons,
                "score": score,
                "firewall_action": "Source IP dynamically placed on blocklist (TTL 300s)",
            },
            headers={"X-Blocked-By": "ThreatEngine-v2"},
        )

    # Throttle handling
    is_throttled = False
    if decision == "throttle":
        is_throttled = True
        await asyncio.sleep(0.5)

    # 4. EXECUTE ROUTE HANDLER
    response = await call_next(request)
    if is_throttled:
        response.headers["X-Throttled"] = "true"

    # Track 404s for path fuzzing detection
    if response.status_code == 404:
        threat_engine.record_404(src_ip)

    # Emit allow / throttle event
    bytes_out = int(response.headers.get("content-length", 500))
    event = {
        "ts": ts,
        "src_ip": src_ip,
        "dst": dest_host,
        "path": path,
        "method": method,
        "status": response.status_code,
        "decision": "throttle" if is_throttled else "allow",
        "score": score,
        "reasons": reasons,
        "severity": severity,
        "user_agent": user_agent,
        "bytes_in": bytes_in,
        "bytes_out": bytes_out,
    }
    await emit_decision_event(event)

    return response


# --- Mock Student Portal HTML Templates ---

PORTAL_BASE_STYLE = """
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
  body { background: #0b1120; color: #f1f5f9; min-height: 100vh; display: flex; flex-direction: column; }
  header { background: #0f172a; border-bottom: 1px solid #1e293b; padding: 14px 28px; display: flex; justify-content: space-between; align-items: center; }
  .brand { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 17px; color: #38bdf8; }
  .badge { background: #0284c7; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-family: monospace; }
  .container { max-width: 900px; margin: 30px auto; padding: 0 20px; flex: 1; width: 100%; }
  .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 24px; margin-bottom: 20px; box-shadow: 0 10px 15px -3px rgba(0,0,0,0.3); }
  h2 { font-size: 20px; margin-bottom: 16px; color: #f8fafc; }
  .form-group { margin-bottom: 16px; }
  label { display: block; font-size: 12px; text-transform: uppercase; color: #94a3b8; margin-bottom: 6px; font-family: monospace; }
  input { width: 100%; padding: 10px 12px; background: #0f172a; border: 1px solid #334155; border-radius: 6px; color: white; font-size: 14px; }
  input:focus { outline: none; border-color: #38bdf8; }
  button { background: #0284c7; color: white; border: none; padding: 10px 18px; border-radius: 6px; font-weight: 600; cursor: pointer; transition: background 0.2s; }
  button:hover { background: #0369a1; }
  table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }
  th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #334155; }
  th { color: #94a3b8; font-family: monospace; font-size: 11px; text-transform: uppercase; }
  .nav-links a { color: #94a3b8; text-decoration: none; margin-left: 18px; font-size: 13px; font-weight: 500; }
  .nav-links a:hover { color: #38bdf8; }
  .alert-box { background: #3b82f615; border: 1px solid #3b82f640; padding: 12px; border-radius: 6px; font-size: 12px; color: #93c5fd; margin-bottom: 16px; }
</style>
"""

# --- Student Portal Routes ---

@app.get("/", response_class=HTMLResponse)
async def portal_index(request: Request):
    """Student portal login page."""
    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse({"portal": "student.college.edu", "status": "online", "login_endpoint": "/login"})

    html = f"""
    <!DOCTYPE html>
    <html>
      <head>
        <title>Student Portal — Login</title>
        {PORTAL_BASE_STYLE}
      </head>
      <body>
        <header>
          <div class="brand">🎓 Apex University <span class="badge">student.college.edu</span></div>
          <div class="nav-links">
            <a href="/courses">Course Catalog</a>
            <a href="/health">Health</a>
          </div>
        </header>
        <div class="container">
          <div class="card" style="max-width: 440px; margin: 40px auto;">
            <h2>Student Sign In</h2>
            <div class="alert-box">
              Demo Credentials:<br/>
              Username: <code>student</code> | Password: <code>college2026</code>
            </div>
            <form action="/login" method="POST">
              <div class="form-group">
                <label>Student ID / Username</label>
                <input type="text" name="username" placeholder="e.g. student" required />
              </div>
              <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" placeholder="••••••••" required />
              </div>
              <button type="submit" style="width: 100%;">Access Portal</button>
            </form>
          </div>
        </div>
      </body>
    </html>
    """
    return HTMLResponse(content=html)


@app.post("/login")
async def portal_login(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
):
    """Authenticate student. On failure, records attempt for brute-force tracking."""
    src_ip = getattr(request.state, "client_ip", None) or (
        request.headers.get("x-forwarded-for", "").split(",")[0].strip() or (
            request.client.host if request.client else "127.0.0.1"
        )
    )

    if username == DEMO_CREDENTIALS["username"] and password == DEMO_CREDENTIALS["password"]:
        # Successful login -> Set session cookie
        if "application/json" in request.headers.get("accept", ""):
            resp = JSONResponse({"status": "authenticated", "student": username, "token": "session-student-ok"})
            resp.set_cookie("student_session", "valid-student-session-2026", httponly=True)
            return resp
        resp = RedirectResponse(url="/dashboard", status_code=303)
        resp.set_cookie("student_session", "valid-student-session-2026", httponly=True)
        return resp

    # Failed login -> Record in threat engine for credential brute force detection
    threat_engine.record_failed_login(src_ip)

    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse(status_code=401, content={"error": "Invalid student credentials"})

    html = f"""
    <!DOCTYPE html>
    <html>
      <head><title>Login Failed</title>{PORTAL_BASE_STYLE}</head>
      <body>
        <div class="container" style="max-width: 440px; margin: 40px auto;">
          <div class="card">
            <h2 style="color: #f87171;">Authentication Failed</h2>
            <p style="font-size: 13px; color: #cbd5e1; margin-bottom: 16px;">Invalid Student ID or Password. Repeated failed attempts trigger firewall lockouts.</p>
            <a href="/" style="color: #38bdf8; text-decoration: none; font-size: 13px;">← Return to Login</a>
          </div>
        </div>
      </body>
    </html>
    """
    return HTMLResponse(status_code=401, content=html)


@app.get("/dashboard", response_class=HTMLResponse)
async def portal_dashboard(request: Request, student_session: Optional[str] = Cookie(None)):
    """Student academic dashboard."""
    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse({
            "student_id": "APX-84920",
            "name": "Alex Mercer",
            "major": "Computer Science & Cybersecurity",
            "gpa": 3.88,
            "credits_completed": 78,
            "standing": "Good",
        })

    html = f"""
    <!DOCTYPE html>
    <html>
      <head><title>Student Dashboard</title>{PORTAL_BASE_STYLE}</head>
      <body>
        <header>
          <div class="brand">🎓 Apex University <span class="badge">student.college.edu</span></div>
          <div class="nav-links">
            <a href="/dashboard">Dashboard</a>
            <a href="/courses">Courses</a>
            <a href="/results">Results</a>
            <a href="/fees">Fees</a>
            <a href="/">Sign Out</a>
          </div>
        </header>
        <div class="container">
          <div class="card">
            <h2>Welcome, Alex Mercer (ID: APX-84920)</h2>
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-top: 15px;">
              <div style="background: #0f172a; padding: 15px; border-radius: 8px;">
                <label>Cumulative GPA</label>
                <p style="font-size: 24px; font-weight: bold; color: #38bdf8;">3.88</p>
              </div>
              <div style="background: #0f172a; padding: 15px; border-radius: 8px;">
                <label>Enrolled Credits</label>
                <p style="font-size: 24px; font-weight: bold; color: #34d399;">16 hrs</p>
              </div>
              <div style="background: #0f172a; padding: 15px; border-radius: 8px;">
                <label>Academic Standing</label>
                <p style="font-size: 18px; font-weight: bold; color: #a78bfa; margin-top: 5px;">Honors Dean's List</p>
              </div>
            </div>
          </div>
        </div>
      </body>
    </html>
    """
    return HTMLResponse(content=html)


@app.get("/courses")
async def portal_courses(request: Request):
    """Course catalog."""
    courses = [
        {"code": "CS-401", "name": "Advanced Network Security", "credits": 4, "instructor": "Dr. Vance"},
        {"code": "CS-415", "name": "Distributed Systems & Telemetry", "credits": 4, "instructor": "Prof. Chen"},
        {"code": "CS-330", "name": "Operating System Internals", "credits": 4, "instructor": "Dr. Kumar"},
        {"code": "CY-220", "name": "Defensive Security & Threat Hunting", "credits": 4, "instructor": "Prof. Davis"},
    ]
    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse({"courses": courses})

    rows = "".join(
        f"<tr><td><b>{c['code']}</b></td><td>{c['name']}</td><td>{c['credits']}</td><td>{c['instructor']}</td><td><button style='padding:4px 10px; font-size:11px;'>Enroll</button></td></tr>"
        for c in courses
    )
    html = f"""
    <!DOCTYPE html>
    <html>
      <head><title>Course Catalog</title>{PORTAL_BASE_STYLE}</head>
      <body>
        <header>
          <div class="brand">🎓 Apex University <span class="badge">student.college.edu</span></div>
          <div class="nav-links"><a href="/dashboard">Dashboard</a><a href="/courses">Courses</a><a href="/results">Results</a></div>
        </header>
        <div class="container">
          <div class="card">
            <h2>Course Catalog & Registration</h2>
            <table>
              <thead><tr><th>Course Code</th><th>Course Title</th><th>Credits</th><th>Instructor</th><th>Action</th></tr></thead>
              <tbody>{rows}</tbody>
            </table>
          </div>
        </div>
      </body>
    </html>
    """
    return HTMLResponse(content=html)


@app.post("/courses/enroll")
async def enroll_course(request: Request, course_code: str = Form("CS-401")):
    return JSONResponse({"status": "enrolled", "course": course_code, "enrolled_at": time.time()})


@app.get("/results")
async def portal_results(request: Request):
    grades = [
        {"term": "Fall 2025", "code": "CS-301", "name": "Computer Networks", "grade": "A", "points": 4.0},
        {"term": "Fall 2025", "code": "CS-302", "name": "Database Systems", "grade": "A-", "points": 3.7},
        {"term": "Spring 2026", "code": "CS-401", "name": "Network Security", "grade": "A", "points": 4.0},
    ]
    return JSONResponse({"grades": grades, "semester_gpa": 3.90})


@app.get("/fees")
async def portal_fees(request: Request):
    return JSONResponse({
        "balance_due": 0.0,
        "status": "Paid in Full",
        "last_payment_date": "2026-09-01",
        "receipt_number": "REC-994812",
    })


@app.get("/health")
async def portal_health():
    """Health status and telemetry."""
    return JSONResponse({
        "status": "online",
        "domain": "student.college.edu",
        "uptime_seconds": round(time.time() - BOOT_TIME, 2),
        "requests_evaluated": _packets_seen_count,
        "blocked_ips_count": blocklist.count(),
    })


@app.get("/admin")
async def portal_admin_honeypot(request: Request):
    """
    Deliberate Honeypot Endpoint.
    Access without a valid admin token triggers a Tier 1 detection signature.
    """
    token = request.headers.get("x-admin-token") or request.query_params.get("token")
    if token == ADMIN_SECRET:
        return JSONResponse({"role": "administrator", "system": "student.college.edu", "authorized": True})

    # Return 403 Forbidden
    return JSONResponse(
        status_code=403,
        content={"error": "Access Denied: Administrative interface is strictly restricted."},
    )


# --- Blocklist Management APIs ---

@app.get("/api/blocked")
async def get_blocked_list():
    """Return all currently active firewall blocked entries."""
    return JSONResponse(blocklist.get_all())


@app.delete("/api/blocked/{ip}")
async def unblock_ip_endpoint(ip: str):
    """Manually unblock an IP."""
    success = blocklist.unblock_ip(ip)
    if not success:
        raise HTTPException(status_code=404, detail=f"IP {ip} not found in blocklist")
    return {"status": "unblocked", "ip": ip}


@app.post("/api/block")
async def block_ip_endpoint(payload: Dict[str, Any]):
    """Manually block an IP on the demo server."""
    ip = payload.get("ip")
    reason = payload.get("reason", "Manual administrator block")
    ttl = int(payload.get("ttl", 300))
    if not ip:
        raise HTTPException(status_code=400, detail="Missing IP")
    entry = blocklist.block_ip(ip, reason, score=1.0, ttl=ttl)
    return {"status": "blocked", "entry": entry.to_dict()}


@app.get("/api/events")
async def get_live_events(limit: int = 100):
    """Return the recent decision events buffer."""
    async with _stats_lock:
        return list(_recent_events)[-limit:]
