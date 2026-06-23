"""
DEV-ONLY test issuer. NOT for production.

Mints tokens for any `sub` (alice, bob, ...) with optional roles, so you can test
object-level authorization: alice reading her own doc vs. trying to read bob's.

  GET  /.well-known/jwks.json    public signing key
  POST /dev/token                mint a JWT (?sub=&roles=&ttl=)
"""
import json
import time
import uuid

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.responses import JSONResponse

ISSUER = "https://dev-issuer.local"
AUDIENCE = "resource-api"

_KID = uuid.uuid4().hex[:8]
_PRIV = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PEM = _PRIV.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)
_JWK = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(_PRIV.public_key()))
_JWK.update({"kid": _KID, "use": "sig", "alg": "RS256"})

app = FastAPI(title="DEV token issuer (TEST ONLY)")


@app.get("/.well-known/jwks.json")
async def jwks():
    return {"keys": [_JWK]}


@app.post("/dev/token")
async def mint(sub: str = "alice", roles: str = "", ttl: int = 300):
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": sub,
        "roles": roles.split() if roles else [],
        "iat": now,
        "exp": now + ttl,
    }
    token = jwt.encode(claims, _PEM, algorithm="RS256", headers={"kid": _KID})
    return JSONResponse({"access_token": token, "sub": sub, "roles": claims["roles"]})
