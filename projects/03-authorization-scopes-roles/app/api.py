"""
Resource server with AUTHORIZATION.

Three routes, increasing privilege — to make authn vs authz concrete:
  GET  /api/profile   any *authenticated* user            (401 if no/invalid token)
  GET  /api/reports   needs scope `reports:read`          (403 if authenticated but lacking it)
  POST /api/admin     needs role `admin`                  (403 if authenticated but not admin)

The 401 vs 403 split is the point: 401 = "I don't know who you are";
403 = "I know exactly who you are, and you're not allowed to do this."
"""
import os

from dotenv import load_dotenv
from fastapi import Depends, FastAPI

from .authz import make_auth
from .verifier import TokenVerifier

load_dotenv()


def _require(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        raise RuntimeError(f"Missing required environment variable: {name} (see .env.example)")
    return val


verifier = TokenVerifier(_require("JWKS_URL"), _require("TOKEN_ISSUER"), _require("TOKEN_AUDIENCE"))
claims, require_scopes, require_role = make_auth(verifier)

app = FastAPI(title="Resource Server — Authorization (scopes & roles)")


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.get("/api/profile")
async def profile(c: dict = Depends(claims)):
    # Authentication only: any valid token may see its own profile.
    return {"sub": c.get("sub"), "scope": c.get("scope"), "roles": c.get("roles", [])}


@app.get("/api/reports")
async def reports(c: dict = Depends(require_scopes("reports:read"))):
    # Authorized only if the verified token carries scope `reports:read`.
    return {"data": "quarterly numbers", "for": c.get("sub")}


@app.post("/api/admin")
async def admin(c: dict = Depends(require_role("admin"))):
    # Authorized only if the verified token has role `admin`.
    return {"message": "admin action performed", "by": c.get("sub")}
