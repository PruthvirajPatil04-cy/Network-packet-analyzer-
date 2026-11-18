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
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any, List
from collections import deque
from contextlib import asynccontextmanager

import bcrypt
import jwt
from fastapi import (
    FastAPI, Request, Response, Form, Depends, HTTPException,
    status, Cookie
)
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
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
SESSION_SECRET = os.environ.get("SESSION_SECRET", "apex-university-jwt-secret-key-2026")
ADMIN_SECRET = os.environ.get("ADMIN_SECRET_TOKEN", "super-secret-admin-token-2026")

# --- Persistent Student Seed Loader (Phase 1.1) ---
SEED_FILE = Path(__file__).resolve().parent / "seed" / "students.json"
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def load_student_db() -> Dict[str, Dict[str, Any]]:
    """Loads student records from seed/students.json into an in-memory database."""
    if not SEED_FILE.exists() or SEED_FILE.stat().st_size == 0:
        raise RuntimeError("Student seed missing. Run: python -m demo_server.seed.hash_passwords")
    try:
        with open(SEED_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not data or not isinstance(data, list):
            raise RuntimeError("Student seed missing. Run: python -m demo_server.seed.hash_passwords")
        return {item["roll"]: item for item in data}
    except Exception as e:
        if isinstance(e, RuntimeError):
            raise
        raise RuntimeError(f"Student seed missing. Run: python -m demo_server.seed.hash_passwords ({e})")


STUDENT_DB = load_student_db()


# --- Authentication & Deterministic Academic Logic ---

def create_session_jwt(student: Dict[str, Any]) -> str:
    """Create a signed HMAC-SHA256 session token with 30-min expiry."""
    payload = {
        "roll": student["roll"],
        "name": student["name"],
        "exp": int(time.time()) + 1800,
        "iat": int(time.time()),
    }
    return jwt.encode(payload, SESSION_SECRET, algorithm="HS256")


def decode_session_jwt(token: Optional[str]) -> Optional[Dict[str, Any]]:
    """Verify and decode a session token."""
    if not token:
        return None
    try:
        return jwt.decode(token, SESSION_SECRET, algorithms=["HS256"])
    except Exception:
        return None


def get_deterministic_results(student: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Generate deterministic grades from roll + course code.
    Results are completely stable across restarts without using random.
    """
    roll = student["roll"]
    enrolled = student.get("enrolled", [])
    grades_cycle = ["A+", "A", "A-", "B+", "B", "B-", "A"]
    points_map = {"A+": 10.0, "A": 9.0, "A-": 8.5, "B+": 8.0, "B": 7.0, "B-": 6.0}
    results = []
    for course in enrolled:
        h_val = int(hashlib.sha256(f"{roll}:{course}".encode("utf-8")).hexdigest(), 16)
        grade = grades_cycle[h_val % len(grades_cycle)]
        results.append({
            "course": course,
            "grade": grade,
            "points": points_map.get(grade, 8.0),
            "credits": 4,
        })
    return results


def get_deterministic_last_paid(student: Dict[str, Any]) -> str:
    """Derive last tuition payment date deterministically from student roll."""
    roll = student["roll"]
    h_val = int(hashlib.md5(roll.encode("utf-8")).hexdigest(), 16)
    day = 1 + (h_val % 25)
    month = 8 if student.get("year", 3) == 3 else 7
    return f"2025-{month:02d}-{day:02d}"


def get_student_ip(roll: Optional[str]) -> Optional[str]:
    """
    Returns the distinct campus IP address assigned to each student.
    Uses database record or derives a deterministic department subnet IP.
    """
    if not roll:
        return None
    student = STUDENT_DB.get(roll)
    if student and student.get("ip"):
        return student["ip"]
    dept = roll[:2].upper()
    dept_map = {"CS": 1, "EC": 2, "ME": 3, "EE": 4}
    dept_id = dept_map.get(dept, 5)
    digits = "".join(ch for ch in roll if ch.isdigit())
    last_num = int(digits[-3:]) if len(digits) >= 3 else 100
    return f"10.20.{dept_id}.{last_num}"

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
    if path in ("/health", "/favicon.ico", "/api/blocked", "/api/events", "/api/block", "/api/docs", "/openapi.json", "/api/server/demo-accounts") or path.startswith("/api/blocked/"):
        return await call_next(request)

    ts = time.time()
    raw_ip = request.headers.get("x-forwarded-for") or (
        request.client.host if request.client else "127.0.0.1"
    )
    src_ip = raw_ip.split(",")[0].strip() if "," in raw_ip else raw_ip.strip()

    # Read body safely for inspection and cache in request.state.body
    body_bytes = await request.body()
    request.state.body = body_bytes
    body_str = body_bytes.decode("utf-8", errors="replace")
    bytes_in = len(body_bytes)

    # Extract authenticated student identity from session JWT if present (Phase 1.2 & 3.3)
    session_cookie = request.cookies.get("session")
    jwt_payload = decode_session_jwt(session_cookie) if session_cookie else None
    student_roll = jwt_payload.get("roll") if jwt_payload else None

    # On login POST, extract roll from body if not yet in cookie
    method = request.method
    if not student_roll and path == "/login" and method == "POST":
        try:
            import urllib.parse
            form_params = urllib.parse.parse_qs(body_str)
            rolls = form_params.get("roll", [])
            if rolls and rolls[0]:
                student_roll = rolls[0].strip()
        except Exception:
            pass

    request.state.student_roll = student_roll

    # Assign distinct campus IP per student when connecting from local loopback (browser / demo desk)
    is_loopback = src_ip in ("127.0.0.1", "::1", "localhost", "testclient")
    if student_roll and (is_loopback or not request.headers.get("x-forwarded-for")):
        student_ip = get_student_ip(student_roll)
        if student_ip:
            src_ip = student_ip

    request.state.client_ip = src_ip

    dest_host = request.headers.get("host", "student.college.edu")
    query_str = request.url.query
    user_agent = request.headers.get("user-agent", "")
    admin_token = request.headers.get("x-admin-token") or request.query_params.get("token")

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
            "roll": student_roll or "",
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
            "roll": student_roll or "",
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

    # Emit allow / throttle event tagged with student roll
    bytes_out = int(response.headers.get("content-length", 500))
    active_roll = getattr(request.state, "student_roll", None) or student_roll
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
        "roll": active_roll or "",
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
    """Student portal login page with collapsible demo credentials expander."""
    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse({
            "portal": "student.college.edu",
            "status": "online",
            "login_endpoint": "/login",
            "seeded_accounts": len(STUDENT_DB),
        })

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"error": None}
    )


@app.post("/login")
async def portal_login(
    request: Request,
    response: Response,
    roll: Optional[str] = Form(None),
    username: Optional[str] = Form(None),
    password: str = Form(...),
):
    """
    Authenticate student against persistent bcrypt-hashed database.
    Sets signed session=<jwt> cookie on success.
    On failure, records attempt for brute-force tracking.
    """
    src_ip = getattr(request.state, "client_ip", None) or (
        request.headers.get("x-forwarded-for", "").split(",")[0].strip() or (
            request.client.host if request.client else "127.0.0.1"
        )
    )

    identifier = (roll or username or "").strip()

    # Legacy demo credentials backwards-compatibility alias
    if identifier == "student" and password == "college2026":
        student = STUDENT_DB.get("CS22B001")
        if student:
            token = create_session_jwt(student)
            request.state.student_roll = student["roll"]
            if "application/json" in request.headers.get("accept", ""):
                resp = JSONResponse({"status": "authenticated", "student": student["name"], "roll": student["roll"], "token": token})
            else:
                resp = RedirectResponse(url="/dashboard", status_code=303)
            resp.set_cookie("session", token, max_age=1800, httponly=True, samesite="lax")
            return resp

    # Look up in persistent student seed database
    student = STUDENT_DB.get(identifier)
    if student:
        pw_hash = student.get("password_hash", "")
        try:
            is_valid = bcrypt.checkpw(password.encode("utf-8"), pw_hash.encode("utf-8"))
        except Exception:
            is_valid = False

        if is_valid:
            token = create_session_jwt(student)
            request.state.student_roll = student["roll"]
            if "application/json" in request.headers.get("accept", ""):
                resp = JSONResponse({
                    "status": "authenticated",
                    "student": student["name"],
                    "roll": student["roll"],
                    "token": token,
                })
            else:
                resp = RedirectResponse(url="/dashboard", status_code=303)
            resp.set_cookie("session", token, max_age=1800, httponly=True, samesite="lax")
            return resp

    # Failed login -> Record in threat engine for credential brute force detection
    threat_engine.record_failed_login(src_ip)

    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse(status_code=401, content={"detail": "invalid credentials", "error": "Invalid student roll number or password"})

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "error": "Invalid Roll Number or Password. Repeated failed attempts trigger firewall lockouts.",
        },
        status_code=401,
    )


@app.get("/dashboard", response_class=HTMLResponse)
async def portal_dashboard(request: Request):
    """
    Student academic dashboard.
    Derives student identity strictly from the cryptographically verified session JWT.
    """
    session_token = request.cookies.get("session")
    payload = decode_session_jwt(session_token) if session_token else None
    if not payload or payload.get("roll") not in STUDENT_DB:
        if "application/json" in request.headers.get("accept", ""):
            raise HTTPException(status_code=401, detail="Authentication required. Please sign in.")
        return RedirectResponse(url="/", status_code=303)

    student = STUDENT_DB[payload["roll"]]
    results = get_deterministic_results(student)
    last_paid = get_deterministic_last_paid(student)

    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse({
            "roll": student["roll"],
            "name": student["name"],
            "program": student["program"],
            "year": student["year"],
            "section": student["section"],
            "cgpa": student["cgpa"],
            "fee_status": student["fee_status"],
            "fee_due": student["fee_due"],
            "enrolled_count": len(student.get("enrolled", [])),
            "recent_login": time.time(),
        })

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "student": student,
            "results": results,
            "last_paid_on": last_paid,
        }
    )


@app.get("/courses")
async def portal_courses(request: Request):
    """Enrolled courses for current student and general registration catalog."""
    session_token = request.cookies.get("session")
    payload = decode_session_jwt(session_token) if session_token else None
    student = STUDENT_DB.get(payload["roll"]) if payload else None

    catalog = [
        {"code": "CS-401", "name": "Advanced Network Security", "credits": 4, "instructor": "Dr. Vance"},
        {"code": "CS-415", "name": "Distributed Systems & Telemetry", "credits": 4, "instructor": "Prof. Chen"},
        {"code": "CS-330", "name": "Operating System Internals", "credits": 4, "instructor": "Dr. Kumar"},
        {"code": "CY-220", "name": "Defensive Security & Threat Hunting", "credits": 4, "instructor": "Prof. Davis"},
    ]

    enrolled = student.get("enrolled", []) if student else []

    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse({
            "roll": student["roll"] if student else None,
            "enrolled": enrolled,
            "courses": catalog,
        })

    rows = "".join(
        f"<tr><td><b>{c['code']}</b></td><td>{c['name']}</td><td>{c['credits']}</td><td>{c['instructor']}</td><td><button style='padding:4px 10px; font-size:11px;'>Enroll</button></td></tr>"
        for c in catalog
    )
    enrolled_html = "".join(f"<li><b>{c}</b></li>" for c in enrolled) if enrolled else "<li>No courses enrolled yet</li>"
    html = f"""
    <!DOCTYPE html>
    <html>
      <head><title>Course Catalog</title>{PORTAL_BASE_STYLE}</head>
      <body>
        <header>
          <div class="brand">🎓 Apex University <span class="badge">student.college.edu</span></div>
          <div class="nav-links"><a href="/dashboard">Dashboard</a><a href="/courses">Courses</a><a href="/results">Results</a><a href="/fees">Fees</a><a href="/logout">Sign Out</a></div>
        </header>
        <div class="container">
          <div class="card">
            <h2>Course Catalog & Registration</h2>
            <div style="margin-bottom: 20px;">
              <h3 style="font-size: 14px; color: #38bdf8; margin-bottom: 8px;">Your Enrolled Courses:</h3>
              <ul style="margin-left: 20px; font-size: 13px; color: #cbd5e1;">{enrolled_html}</ul>
            </div>
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
async def enroll_course(request: Request, course_code: Optional[str] = Form(None)):
    """Enroll student in a course; rejects if already enrolled."""
    session_token = request.cookies.get("session")
    payload = decode_session_jwt(session_token) if session_token else None
    if not payload or payload.get("roll") not in STUDENT_DB:
        raise HTTPException(status_code=401, detail="Authentication required to enroll in courses")

    student = STUDENT_DB[payload["roll"]]

    # Handle JSON payload if course_code is not supplied in Form
    if not course_code and getattr(request.state, "body", None):
        try:
            body_json = json.loads(request.state.body.decode("utf-8", errors="ignore"))
            course_code = body_json.get("course_code") or body_json.get("course")
        except Exception:
            pass

    course_code = course_code or "CS-401"
    enrolled_list = student.setdefault("enrolled", [])
    if course_code in enrolled_list:
        return JSONResponse(
            status_code=400,
            content={"detail": f"Already enrolled in {course_code}", "roll": student["roll"]}
        )

    enrolled_list.append(course_code)
    if _redis_client:
        try:
            await _redis_client.sadd(f"student:{student['roll']}:courses", course_code)
        except Exception:
            pass

    return JSONResponse({
        "status": "enrolled",
        "roll": student["roll"],
        "course": course_code,
        "enrolled": enrolled_list,
        "enrolled_at": time.time(),
    })


@app.get("/results")
async def portal_results(request: Request):
    """
    Per-course deterministic grade rows.
    Cross-student isolation enforced: returns only the authenticated student's results.
    """
    session_token = request.cookies.get("session")
    payload = decode_session_jwt(session_token) if session_token else None
    if not payload or payload.get("roll") not in STUDENT_DB:
        raise HTTPException(status_code=401, detail="Authentication required to view academic results")

    student = STUDENT_DB[payload["roll"]]
    results = get_deterministic_results(student)

    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse({
            "roll": student["roll"],
            "name": student["name"],
            "cgpa": student["cgpa"],
            "results": results,
            "grades": results,
        })

    rows = "".join(
        f"<tr><td><b>{r['course']}</b></td><td>{r['credits']}</td><td><span style='color:#38bdf8; font-weight:bold;'>{r['grade']}</span></td><td>{r['points']}</td></tr>"
        for r in results
    )
    html = f"""
    <!DOCTYPE html>
    <html>
      <head><title>Academic Results — {student['name']}</title>{PORTAL_BASE_STYLE}</head>
      <body>
        <header>
          <div class="brand">🎓 Apex University <span class="badge">student.college.edu</span></div>
          <div class="nav-links"><a href="/dashboard">Dashboard</a><a href="/courses">Courses</a><a href="/results">Results</a><a href="/fees">Fees</a><a href="/logout">Sign Out</a></div>
        </header>
        <div class="container">
          <div class="card">
            <h2>Academic Results — {student['name']} ({student['roll']})</h2>
            <p style="color: #94a3b8; font-size: 13px; margin-bottom: 15px;">Cumulative GPA: <strong style="color: #38bdf8;">{student['cgpa']}</strong></p>
            <table>
              <thead><tr><th>Course</th><th>Credits</th><th>Grade</th><th>Grade Points</th></tr></thead>
              <tbody>{rows}</tbody>
            </table>
          </div>
        </div>
      </body>
    </html>
    """
    return HTMLResponse(content=html)


@app.get("/fees")
async def portal_fees(request: Request):
    """Student tuition status and fee dues."""
    session_token = request.cookies.get("session")
    payload = decode_session_jwt(session_token) if session_token else None
    if not payload or payload.get("roll") not in STUDENT_DB:
        raise HTTPException(status_code=401, detail="Authentication required to view fee balance")

    student = STUDENT_DB[payload["roll"]]
    last_paid = get_deterministic_last_paid(student)

    return JSONResponse({
        "roll": student["roll"],
        "name": student["name"],
        "fee_status": student["fee_status"],
        "fee_due": student["fee_due"],
        "currency": "INR",
        "last_paid_on": last_paid,
        "balance_due": float(student["fee_due"]),
        "status": student["fee_status"],
    })


@app.get("/logout")
async def portal_logout():
    """Sign out student and invalidate session cookie."""
    resp = RedirectResponse(url="/", status_code=303)
    resp.delete_cookie("session")
    return resp


@app.get("/api/server/demo-accounts", tags=["Demo Server"])
async def get_demo_accounts():
    """
    Returns sanitized student roster without passwords or password hashes.
    Safe reference for evaluation and UI dropdowns.
    """
    roster = [
        {
            "roll": s["roll"],
            "name": s["name"],
            "program": s["program"],
            "year": s["year"],
            "email": s["email"],
            "section": s.get("section", "A"),
            "ip": s.get("ip") or get_student_ip(s.get("roll")),
            "enrolled_count": len(s.get("enrolled", [])),
        }
        for s in STUDENT_DB.values()
    ]
    return {"accounts": roster, "count": len(roster)}


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
