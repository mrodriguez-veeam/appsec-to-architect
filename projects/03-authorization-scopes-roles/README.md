# 03 — Authorization: scopes & roles

Builds on project 02. Where 02 proved **who** a token is (authentication → `401`), this project
controls **what that identity is allowed to do** (authorization → `403`).

**The core idea:** `401` ≠ `403`.
- `401 Unauthorized` = *"I don't know who you are"* (no/invalid token).
- `403 Forbidden` = *"I know exactly who you are — and you're not allowed to do this."*

## What it demonstrates
- **Deny-by-default** authorization layered on top of token verification.
- **Scope** checks (`reports:read`) and **role** checks (`admin`).
- The `401` → `403` distinction, shown live with the same endpoints and different tokens.
- Authorization decisions read from the **signed token's claims** — trusted because verified, but
  always **enforced server-side** (never from a client-supplied header/query/body).

## Routes (increasing privilege)
| Route | Requires | Fails with |
|-------|----------|-----------|
| `GET /api/profile` | any valid token (authn only) | `401` if no/invalid token |
| `GET /api/reports` | scope `reports:read` | `401` if unauthenticated, **`403`** if authenticated but missing the scope |
| `POST /api/admin` | role `admin` | `401` / **`403`** |

## Run (offline, with the dev issuer)
```bash
cd projects/03-authorization-scopes-roles
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

# terminal 1 — dev issuer (mints tokens with whatever scope/roles you ask for)
uvicorn devissuer.issuer:app --port 9002
# terminal 2 — the authorization-enforcing API
uvicorn app.api:app --port 8002
```

### See authn vs authz
```bash
# no token -> 401 (don't know who you are)
curl -s -o /dev/null -w '%{http_code}\n' localhost:8002/api/reports

# authenticated but NO scope -> 403 (know you, not allowed)
T1=$(curl -s -X POST 'localhost:9002/dev/token?sub=alice' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $T1" localhost:8002/api/reports

# authenticated WITH the scope -> 200
T2=$(curl -s -X POST 'localhost:9002/dev/token?sub=alice&scope=reports:read' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s -H "Authorization: Bearer $T2" localhost:8002/api/reports; echo

# admin role gate
T3=$(curl -s -X POST 'localhost:9002/dev/token?sub=alice&roles=admin' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s -X POST -H "Authorization: Bearer $T3" localhost:8002/api/admin; echo
```

## Validate REAL tokens
Point `.env` at your IdP (JWKS / issuer / audience) and map the route requirements to your IdP's
scope/role claim names (Entra uses `scp` for scopes and `roles` for app roles).

## What I built / what I learned
> _(my notes — filled in after running it)_
- …

## Possible extensions
- Hierarchical / wildcard scopes; scope-to-permission mapping
- Resource-level checks (owner-only access), not just endpoint-level
- Policy engine (OPA / Cedar) instead of inline checks
- Negative-path tests for every 401 and 403
