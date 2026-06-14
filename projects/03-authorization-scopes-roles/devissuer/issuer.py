"""
DEV-ONLY test issuer. NOT for production.

Mints tokens with whatever scopes/roles you ask for, so you can see the
difference between *authenticated* (a valid token) and *authorized* (a token
that also carries the required scope/role).

  GET  /.well-known/jwks.json    public signing key(s)
  POST /dev/token                mint a JWT (?sub=&scope=&roles=&ttl=)
                                 e.g. ?sub=alice&scope=reports:read&roles=admin
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
async def mint(sub: str = "alice", scope: str = "", roles: str = "", ttl: int = 300):
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": sub,
        "scope": scope,                              # space-delimited, e.g. "reports:read"
        "roles": roles.split() if roles else [],     # e.g. "admin"
        "iat": now,
        "exp": now + ttl,
    }
    token = jwt.encode(claims, _PEM, algorithm="RS256", headers={"kid": _KID})
    return JSONResponse({"access_token": token, "scope": scope, "roles": claims["roles"]})
