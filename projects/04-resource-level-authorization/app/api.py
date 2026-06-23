"""
Resource / object-level authorization — preventing IDOR / BOLA.

Project 03 controlled WHICH endpoints you can call. But the #1 API risk
(OWASP API1:2023, Broken Object Level Authorization) is a valid, authorized user
reading SOMEONE ELSE'S object by changing the id in the URL. Endpoint-level checks
don't catch that — you need a per-object ownership check on every data access.

This app exposes the SAME read two ways so you can see the bug and the fix:
  GET /api/insecure/documents/{id}   DELIBERATELY VULNERABLE (no ownership check) — for teaching
  GET /api/documents/{id}            SECURE (checks owner == caller, or admin)

Seed data: alice owns a1,a2 ; bob owns b1.
"""
import os

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException

from . import store
from .verifier import TokenError, TokenVerifier

load_dotenv()


def _require(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        raise RuntimeError(f"Missing required environment variable: {name} (see .env.example)")
    return val


verifier = TokenVerifier(_require("JWKS_URL"), _require("TOKEN_ISSUER"), _require("TOKEN_AUDIENCE"))
app = FastAPI(title="Resource-level authorization (IDOR/BOLA)")


def claims(authorization: str = Header(default="")) -> dict:
    """Authentication only (→ 401). Every route below is for a valid identity."""
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")
    try:
        return verifier.verify(token)
    except TokenError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def _is_admin(c: dict) -> bool:
    roles = c.get("roles") or []
    if isinstance(roles, str):
        roles = roles.split()
    return "admin" in roles


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.get("/api/documents")
async def my_documents(c: dict = Depends(claims)):
    # Safe by construction: only ever returns the caller's own documents.
    return store.list_for(c["sub"])


@app.get("/api/insecure/documents/{doc_id}")
async def insecure_get(doc_id: str, c: dict = Depends(claims)):
    # !!! DELIBERATELY VULNERABLE (IDOR / BOLA) — DO NOT COPY !!!
    # It authenticates (valid token required) but NEVER checks who owns the doc,
    # so any logged-in user can read anyone's record by changing {doc_id}.
    doc = store.get(doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="not found")
    return doc


@app.get("/api/documents/{doc_id}")
async def secure_get(doc_id: str, c: dict = Depends(claims)):
    # SECURE: object-level check — you may read it only if you own it (or are admin).
    doc = store.get(doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="not found")
    if doc["owner"] != c["sub"] and not _is_admin(c):
        # 403 makes the lesson clear. Hardened alternative: return 404 so you don't
        # even reveal the object exists (prevents id enumeration) — see DESIGN.md.
        raise HTTPException(status_code=403, detail="not your document")
    return doc
