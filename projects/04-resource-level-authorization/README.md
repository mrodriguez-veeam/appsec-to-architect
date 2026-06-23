# 04 — Resource-level authorization (IDOR / BOLA)

Project 03 controlled **which endpoints** you can call. This one controls **which objects** you can
touch — the difference that stops the #1 API security risk: **Broken Object Level Authorization**
(OWASP API1:2023), a.k.a. **IDOR** (Insecure Direct Object Reference).

**The bug in one sentence:** a logged-in, *authorized* user reads someone else's record by changing
an id in the URL — because the endpoint checks *"are you allowed to call this route?"* but never
*"do you own THIS specific object?"*

This app exposes the **same read two ways** so you can see the hole and the fix side by side.

## Routes
| Route | Behavior |
|-------|----------|
| `GET /api/documents` | lists **only your own** documents (safe by construction) |
| `GET /api/insecure/documents/{id}` | **⚠️ DELIBERATELY VULNERABLE** — returns any doc to any logged-in user (IDOR) |
| `GET /api/documents/{id}` | **SECURE** — returns the doc only if you **own it** (or are `admin`), else `403` |

Seed data: **alice** owns `a1`, `a2`; **bob** owns `b1`.

## Run (offline)
```bash
cd projects/04-resource-level-authorization
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

# terminal 1 — dev issuer
uvicorn devissuer.issuer:app --port 9003
# terminal 2 — the API
uvicorn app.api:app --port 8003
```

## See the vulnerability, then the fix
```bash
# log in AS ALICE
ALICE=$(curl -s -X POST 'localhost:9003/dev/token?sub=alice' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

# 1) alice reads HER OWN doc on the secure route -> 200
curl -s -H "Authorization: Bearer $ALICE" localhost:8003/api/documents/a1; echo

# 2) alice tries BOB's doc on the secure route -> 403 (object-level check stops her)
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $ALICE" localhost:8003/api/documents/b1

# 3) alice tries BOB's doc on the INSECURE route -> 200  *** THE LEAK (IDOR) ***
curl -s -H "Authorization: Bearer $ALICE" localhost:8003/api/insecure/documents/b1; echo

# 4) an admin reads bob's doc on the secure route -> 200 (legitimate override)
ADMIN=$(curl -s -X POST 'localhost:9003/dev/token?sub=carol&roles=admin' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s -H "Authorization: Bearer $ADMIN" localhost:8003/api/documents/b1; echo
```
Step 3 is the whole point: alice is **fully authenticated and authorized to call the route**, yet
walks out with **bob's medical record** — purely because that route skipped the ownership check.

## What I built / what I learned
> _(my notes — filled in after running it)_
- …

## Possible extensions
- Return `404` instead of `403` for non-owned objects (don't reveal existence) — see DESIGN.md
- Object-level checks on write/delete, not just read
- Centralize the check (decorator / dependency) so no endpoint can forget it
- Negative-path tests for every cross-user access
