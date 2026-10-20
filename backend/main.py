import os, json, secrets, sqlite3, hashlib, time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.middleware.cors import CORSMiddlewareapp.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://secureshare-cyan.vercel.app",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-Admin-Key"],
)
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

HERE = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("SECURESHARE_DB", str(HERE / "secureshare.db")))
ADMIN_KEY = os.getenv("SECURESHARE_ADMIN_KEY", "replace-this-with-a-long-random-admin-key")
app = FastAPI(title="SecureShare API", version="1.0.0", description="Encrypted transfer storage prototype")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173","http://127.0.0.1:5173"], allow_credentials=False, allow_methods=["GET","POST","OPTIONS"], allow_headers=["Content-Type","X-Admin-Key"])

def now(): return datetime.now(timezone.utc)
def iso(dt): return dt.isoformat()
def connect():
    c=sqlite3.connect(DB_PATH, timeout=10); c.row_factory=sqlite3.Row; return c
def init_db():
    with connect() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS transfers (
          code TEXT PRIMARY KEY, encrypted_package TEXT NOT NULL, filename TEXT NOT NULL,
          transfer_type TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
          max_downloads INTEGER NOT NULL, downloads INTEGER NOT NULL DEFAULT 0,
          revoked INTEGER NOT NULL DEFAULT 0, revoke_token_hash TEXT NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS audit_events (
          id TEXT PRIMARY KEY, event_type TEXT NOT NULL, detail TEXT NOT NULL,
          created_at TEXT NOT NULL, transfer_code TEXT)""")
        c.commit()
init_db()

def event(event_type, detail, code=None):
    with connect() as c:
        c.execute("INSERT INTO audit_events VALUES (?,?,?,?,?)",(secrets.token_hex(12),event_type,detail,iso(now()),code)); c.commit()
class TransferCreate(BaseModel):
    encrypted_package: dict[str, Any]
    filename: str = Field(min_length=1,max_length=255)
    transfer_type: str = Field(pattern="^(file|message)$")
    expiry_hours: int = Field(default=24, ge=1, le=168)
    max_downloads: int = Field(default=3, ge=1, le=10)
class EmptyBody(BaseModel): pass
class ConfirmBody(BaseModel): pass
class RevokeBody(BaseModel): revoke_token: str = Field(min_length=1,max_length=256)

@app.middleware("http")
async def simple_rate_limit(request: Request, call_next):
    # Lightweight in-memory IP throttle for this single-process demo, not production-grade.
    client=request.client.host if request.client else "unknown"; key=(client, int(time.time()//60))
    counts=getattr(app.state,"rate_counts",{})
    counts[key]=counts.get(key,0)+1; app.state.rate_counts=counts
    if counts[key] > 180:
        event("rate_limit_blocked",f"Temporary request limit exceeded for {client}")
        return JSONResponse(status_code=429,content={"detail":"Rate limit exceeded; try again later."})
    return await call_next(request)

@app.get("/api/health")
def health():
    try:
        with connect() as c: c.execute("SELECT 1")
        return {"status":"ok","application":"SecureShare","message":"Backend is running","database":"connected"}
    except Exception:
        raise HTTPException(503,"Database unavailable")

@app.post("/api/transfers")
def create_transfer(payload: TransferCreate, request: Request):
    pkg=payload.encrypted_package
    if pkg.get("algorithm")!="AES-256-GCM" or not all(k in pkg for k in ("salt","iv","ciphertext","kdf")):
        raise HTTPException(400,"Invalid encrypted package format")
    if len(json.dumps(pkg)) > 22*1024*1024:
        raise HTTPException(413,"Encrypted package too large")
    code=secrets.token_urlsafe(9)
    revoke_token=secrets.token_urlsafe(24)
    created=now(); expires=created+timedelta(hours=payload.expiry_hours)
    with connect() as c:
        c.execute("INSERT INTO transfers(code,encrypted_package,filename,transfer_type,created_at,expires_at,max_downloads,downloads,revoked,revoke_token_hash) VALUES(?,?,?,?,?,?,?,?,?,?)",
          (code,json.dumps(pkg),payload.filename,payload.transfer_type,iso(created),iso(expires),payload.max_downloads,0,0,hashlib.sha256(revoke_token.encode()).hexdigest()))
        c.commit()
    event("transfer_created",f"Created {payload.transfer_type} transfer",code)
    return {"code":code,"revoke_token":revoke_token,"created_at":iso(created),"expires_at":iso(expires),"max_downloads":payload.max_downloads,"transfer_type":payload.transfer_type}

@app.get("/api/transfers/{code}")
def transfer_info(code: str):
    with connect() as c: row=c.execute("SELECT code,filename,transfer_type,created_at,expires_at,max_downloads,downloads,revoked FROM transfers WHERE code=?",(code,)).fetchone()
    if not row: raise HTTPException(404,"Transfer not found")
    return dict(row)

@app.post("/api/transfers/{code}/retrieve")
def retrieve(code: str, request: Request):
    with connect() as c:
        row=c.execute("SELECT * FROM transfers WHERE code=?",(code,)).fetchone()
        if not row: raise HTTPException(404,"Transfer not found")
        if row["revoked"]: event("retrieve_rejected","Attempt to retrieve revoked transfer",code); raise HTTPException(410,"This transfer has been revoked")
        if now() >= datetime.fromisoformat(row["expires_at"]): event("retrieve_rejected","Attempt to retrieve expired transfer",code); raise HTTPException(410,"This transfer has expired")
        if row["downloads"] >= row["max_downloads"]: event("retrieve_rejected","Transfer retrieval limit reached",code); raise HTTPException(410,"Retrieval limit reached")
        # Reserve a retrieval before returning ciphertext to prevent parallel requests exceeding the cap.
        c.execute("UPDATE transfers SET downloads=downloads+1 WHERE code=? AND downloads < max_downloads",(code,))
        if c.total_changes < 1: raise HTTPException(410,"Retrieval limit reached")
        c.commit()
    event("transfer_retrieved","Encrypted package retrieved; client decryption is required",code)
    return {"code":row["code"],"filename":row["filename"],"transfer_type":row["transfer_type"],"encrypted_package":json.loads(row["encrypted_package"]),"retrievals_remaining":max(0,row["max_downloads"]-(row["downloads"]+1))}

@app.post("/api/transfers/{code}/confirm")
def confirm(code: str, body: ConfirmBody):
    # Retrieval count is reserved when ciphertext is returned; no secret/plaintext is sent here.
    return {"status":"ok","message":"Retrieval already counted by the API."}

@app.post("/api/transfers/{code}/revoke")
def revoke(code: str, body: RevokeBody):
    with connect() as c:
        row=c.execute("SELECT revoke_token_hash,revoked FROM transfers WHERE code=?",(code,)).fetchone()
        if not row: raise HTTPException(404,"Transfer not found")
        if not secrets.compare_digest(row["revoke_token_hash"],hashlib.sha256(body.revoke_token.encode()).hexdigest()):
            event("revoke_rejected","Invalid revocation token",code); raise HTTPException(403,"Invalid revocation token")
        c.execute("UPDATE transfers SET revoked=1 WHERE code=?",(code,));c.commit()
    event("transfer_revoked","Transfer revoked using revocation token",code)
    return {"status":"ok","code":code,"revoked":True}

@app.get("/api/admin/events")
def admin_events(event_type: str="all", q: str="", x_admin_key: str=Header(default="",alias="X-Admin-Key")):
    if not ADMIN_KEY or ADMIN_KEY=="replace-this-with-a-long-random-admin-key" or not secrets.compare_digest(x_admin_key,ADMIN_KEY):
        event("admin_access_rejected","Rejected unauthenticated audit log access")
        raise HTTPException(401,"Valid administrator key required. Configure SECURESHARE_ADMIN_KEY in backend/.env.")
    query="SELECT id,event_type,detail,created_at,transfer_code FROM audit_events WHERE 1=1"; args=[]
    if event_type!="all": query+=" AND event_type=?";args.append(event_type)
    if q: query+=" AND (event_type LIKE ? OR transfer_code LIKE ? OR detail LIKE ?)";args.extend([f"%{q}%"]*3)
    query+=" ORDER BY created_at DESC LIMIT 250"
    with connect() as c: rows=c.execute(query,args).fetchall()
    return {"events":[{"id":r["id"],"type":r["event_type"],"detail":r["detail"],"at":r["created_at"],"transfer_code":r["transfer_code"]} for r in rows]}

@app.get("/")
def root(): return {"application":"SecureShare","docs":"/docs","health":"/api/health"}
