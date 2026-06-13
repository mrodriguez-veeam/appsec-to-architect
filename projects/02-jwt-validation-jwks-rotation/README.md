# 02 — JWT validation + JWKS key rotation

A **resource server**: a protected API that accepts a bearer **JWT access token** and *verifies* it
before trusting anything. This is the other half of project 01 — where 01 *consumed* identity at
login, 02 *validates* tokens on every request.

It's the hands-on form of the project-01 thesis: **anyone can read a JWT; trust comes only from
verification.**

## What it demonstrates
- Verifying a bearer JWT: **signature** (against the JWKS key whose `kid` matches), `iss`, `aud`, `exp`.
- **Algorithm pinning** (`RS256` only) — defuses `alg=none` and HS/RS algorithm-confusion attacks.
- **JWKS caching + graceful key rotation** — an unknown `kid` triggers a refetch; old keys keep
  working until their tokens expire.
- **Fail closed** — any failure → `401`, generic message.
- A **dev-only token issuer** so you can mint test tokens *and force a key rotation* offline.

Crypto is handled by **PyJWT** (hardened) — no hand-rolled JOSE.

## Layout
```
app/verifier.py     reusable token verifier (the secure core)
app/api.py          FastAPI resource server: GET /api/protected (Bearer required)
devissuer/issuer.py DEV-ONLY test IdP: /.well-known/jwks.json, /dev/token, /dev/rotate
```

## Run it (offline, with the dev issuer)
```bash
cd projects/02-jwt-validation-jwks-rotation
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # defaults already point at the local dev issuer

# terminal 1 — the test issuer (publishes JWKS, mints tokens)
uvicorn devissuer.issuer:app --port 9000

# terminal 2 — the resource server you're testing
uvicorn app.api:app --port 8001
```

### Exercise it
```bash
# no token -> 401
curl -i localhost:8001/api/protected

# mint a token from the dev issuer, then call the API with it -> 200 + claims
TOKEN=$(curl -s -X POST 'localhost:9000/dev/token?sub=alice' | python -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s -H "Authorization: Bearer $TOKEN" localhost:8001/api/protected

# tamper one character of the token -> 401 (signature fails)
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer ${TOKEN}x" localhost:8001/api/protected
```

### See key rotation work
```bash
curl -s -X POST localhost:9000/dev/rotate        # IdP rotates: new active kid, old key still published
NEW=$(curl -s -X POST 'localhost:9000/dev/token?sub=alice' | python -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s -H "Authorization: Bearer $NEW" localhost:8001/api/protected   # 200: server saw an unknown kid, refetched JWKS, validated
# the OLD $TOKEN still validates too, until it expires — graceful rotation
```

## Validate REAL tokens (e.g. Entra)
Point `.env` at your IdP's JWKS / issuer / audience (see the commented example in `.env.example`),
restart `app.api`, and send a real access token whose `aud` is your API.

## What I built / what I learned
> _(my notes — filled in after running it)_
- …

## Possible extensions
- `scope` / role-based authorization (authz) on top of authn
- Reject tokens missing `kid`; pin acceptable `kid`s
- Clock-skew leeway; `nbf` handling
- Negative-path tests (alg=none, wrong aud, expired, unknown kid)
