"""
Resource server — a protected API that requires a valid bearer JWT.

Every request to a protected route must carry `Authorization: Bearer <jwt>`, and
the token is verified (signature + iss/aud/exp) before any handler runs. Token
validation lives in verifier.py; this file is just the HTTP wiring.

Run:  see README.md.
"""
import os

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException

from .verifier import TokenError, TokenVerifier

load_dotenv()


def _require(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        raise RuntimeError(f"Missing required environment variable: {name} (see .env.example)")
    return val


JWKS_URL = _require("JWKS_URL")
ISSUER   = _require("TOKEN_ISSUER")
AUDIENCE = _require("TOKEN_AUDIENCE")

verifier = TokenVerifier(JWKS_URL, ISSUER, AUDIENCE)
app = FastAPI(title="Resource Server — JWT validation")


def bearer_claims(authorization: str = Header(default="")) -> dict:
    """FastAPI dependency: extract + verify the bearer token, or 401."""
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")
    try:
        return verifier.verify(token)
    except TokenError:
        # Generic message to the caller; details stay server-side.
        raise HTTPException(status_code=401, detail="Invalid or expired token")


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.get("/api/protected")
async def protected(claims: dict = Depends(bearer_claims)):
    # Reached only if the token was authentic and intended for this API.
    return {
        "message": "token accepted",
        "sub": claims.get("sub"),
        "iss": claims.get("iss"),
        "aud": claims.get("aud"),
        "scope": claims.get("scope"),
        "exp": claims.get("exp"),
    }
