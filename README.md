# SecureShare full-stack prototype

A runnable React + Vite frontend and FastAPI + SQLite backend inspired by your screenshots.

## What works in this build
- Responsive dashboard with API health status and session counters.
- Browser-side AES-256-GCM encryption using Web Crypto API and PBKDF2-SHA-256 (310,000 iterations), random salt and 96-bit IV.
- Encrypted file and text-message transfer creation; only ciphertext package is sent to API.
- Retrieval of encrypted package and browser-side decryption; decrypted files are downloaded locally.
- Expiry and retrieval caps enforced by API, plus token-protected revocation.
- SQLite transfer metadata and server-side audit events; admin audit endpoint protected by a configured key.
- RSA-OAEP 3072-bit or ECDH P-256 key generation, public-key JSON export/import, encrypted private-key backup export/restore. These key tools are separate from the passphrase transfer workflow.
- Local browser session history, error feedback and responsive design.

## Honest prototype limitations
- No real user account system; the user label is local/demo UI only.
- Browser history is session-local, not synced to an account.
- Public-key import/export is a management utility and is not integrated into file transfer encryption.
- Rate limiting is an in-memory, single-process demo throttle, not a production control.
- This is not independently security-audited. Use HTTPS and proper identity, secrets management, durable storage, concurrency tests, CSRF/origin policy, monitoring, backup and recovery before handling real confidential data.
- Retrieval allowance is consumed when encrypted content is returned, even if decryption fails.
- This is a prototype, not a guarantee of end-to-end security.

## Run on macOS using Terminal

Requirements: Node.js 20+ and Python 3.10+.

### 1. Backend
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export SECURESHARE_ADMIN_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
uvicorn main:app --reload --port 8000
```
Keep this terminal running. Copy the printed admin key value if you want to use the audit page; because the export is for this shell session, keep the backend in the same terminal. For persistent configuration, create `backend/.env` and export variables manually or use a process manager that loads it.

### 2. Frontend (new Terminal tab)
```bash
cd frontend
npm install
npm run dev
```
Open http://localhost:5173.

### Admin key
If the backend terminal's generated key is still in that running shell, the shell environment is inherited by uvicorn. To view it in another terminal, easiest is set a known key before starting:
```bash
export SECURESHARE_ADMIN_KEY='use-a-long-random-private-value-here'
uvicorn main:app --reload --port 8000
```
Then enter the same value on the Security activity page. Do not use the example value for anything public.

## Verify
- http://127.0.0.1:8000/api/health
- http://127.0.0.1:8000/docs

Demo: send a small file/message using a 12+ character passphrase, copy the transfer code, open Receive, enter the code and the same passphrase. Test a wrong passphrase using a disposable transfer; it should fail AES-GCM authentication. Test expiry, retrieval limits and revocation.
