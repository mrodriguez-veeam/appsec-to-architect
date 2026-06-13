# 01 — OAuth2 / OIDC: Authorization Code + PKCE

A minimal **OpenID Connect relying party** (the application that logs users in) implemented
securely against any OIDC provider — Entra ID, Okta, Auth0, Google, Keycloak.

This is the foundational browser-based login flow used across the industry. The point of the
project is to implement it *correctly* — with PKCE, state, nonce, and full ID-token validation —
and to be able to explain **why** each control exists (see [`DESIGN.md`](DESIGN.md)).

## What it demonstrates
- Authorization Code flow with **PKCE (S256)**
- **state** (CSRF protection) and **nonce** (replay protection)
- **OIDC discovery** (`.well-known/openid-configuration`) and **JWKS**-based ID-token signature checks
- **ID-token validation**: `iss`, `aud`, `exp`, `nonce`
- Secrets kept out of code; **secure session cookie** (HttpOnly, SameSite, Secure in prod)
- **Fail-closed** error handling (no session on any validation failure)

Built on **Authlib**, a hardened OAuth/OIDC library — the secure default is to use a vetted
library, not to hand-roll token/crypto handling.

## Prerequisites
- Python 3.11+
- An app registration in an OIDC provider with redirect URI `http://localhost:8000/auth/callback`

### Register the app (any one provider)
- **Entra ID:** App registrations → New → Web → redirect URI above → add a client secret.
  Issuer is `https://login.microsoftonline.com/<tenant-id>/v2.0`.
- **Okta:** Applications → Create → Web → redirect URI above. Issuer `https://<org>.okta.com/oauth2/default`.
- **Auth0/Google/Keycloak:** create a "web application" client with the same redirect URI.

## Run
```bash
cd projects/01-oauth2-oidc-pkce
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env          # then fill in issuer + client id/secret
python -c "import secrets; print(secrets.token_urlsafe(48))"   # paste into SESSION_SECRET

uvicorn app.main:app --reload --port 8000
# open http://localhost:8000  ->  Log in with OIDC
```

## Endpoints
| Route | Purpose |
|-------|---------|
| `/` | shows sign-in state |
| `/login` | starts the flow (builds the PKCE/state/nonce request) |
| `/auth/callback` | validates the response, exchanges the code, establishes the session |
| `/me` | returns the stored user claims (401 if not authenticated) |
| `/logout` | clears the local session |

## What I built / what I learned
> _(my notes — filled in as I go)_
- …
- …

## Possible extensions
- Refresh-token handling with rotation + revocation
- RP-initiated (provider-side) logout via the `end_session_endpoint`
- Token introspection for opaque access tokens
- Automated tests for the negative paths (bad `state`, bad `nonce`, expired ID token)
