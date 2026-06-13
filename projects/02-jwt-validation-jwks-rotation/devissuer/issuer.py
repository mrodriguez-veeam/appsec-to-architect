"""
DEV-ONLY test token issuer.  NOT a real IdP and NOT for production.

It exists so you can exercise the resource server offline and — importantly —
*demonstrate key rotation*, which you can't force a real IdP to do on demand.

Endpoints:
  GET  /.well-known/jwks.json   public keys for all currently-published kids
  POST /dev/token               mint a signed RS256 test JWT (?sub=&kid=&ttl=)
  POST /dev/rotate              generate a NEW signing key, make it active
                                (old keys stay published so existing tokens still verify)

Keys live in memory only and reset on restart.
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

_KEYS: dict[str, dict] = {}   # kid -> {"pem": bytes, "jwk": dict}
_ACTIVE_KID: str = ""


def _new_key() -> str:
    """Generate an RSA keypair, publish its public JWK, return the new kid."""
    global _ACTIVE_KID
    kid = uuid.uuid4().hex[:8]
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(priv.public_key()))
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    _KEYS[kid] = {"pem": pem, "jwk": jwk}
    _ACTIVE_KID = kid
    return kid


_new_key()  # start with one active signing key

app = FastAPI(title="DEV token issuer (TEST ONLY)")


@app.get("/.well-known/jwks.json")
async def jwks():
    # The public half of every published key. The resource server fetches this.
    return {"keys": [k["jwk"] for k in _KEYS.values()]}


@app.post("/dev/token")
async def mint_token(sub: str = "alice", kid: str = "", ttl: int = 300):
    use_kid = kid or _ACTIVE_KID
    if use_kid not in _KEYS:
        return JSONResponse({"error": f"unknown kid {use_kid!r}"}, status_code=400)
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": sub,
        "scope": "read",
        "iat": now,
        "exp": now + ttl,
    }
    token = jwt.encode(claims, _KEYS[use_kid]["pem"], algorithm="RS256",
                       headers={"kid": use_kid})
    return {"access_token": token, "kid": use_kid, "expires_in": ttl}


@app.post("/dev/rotate")
async def rotate():
    """Simulate an IdP key rotation: new active key; old keys stay published."""
    new_kid = _new_key()
    return {"active_kid": new_kid, "published_kids": list(_KEYS)}
