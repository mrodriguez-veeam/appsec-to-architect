# DESIGN — OIDC Relying Party (Authorization Code + PKCE)

This document is the "architect" half of the project: the design, the security decisions, and the
threat model. The goal is to show not just that the flow works, but that I can reason about *why*
it's built this way and *how it fails safely*.

## 1. Context & scope
- **Role implemented:** the **Relying Party (RP)** — the app that delegates authentication to an
  Identity Provider (IdP) and consumes the resulting identity.
- **In scope:** interactive, browser-based user login via OIDC; secure session establishment.
- **Out of scope (intentionally):** running our own IdP, authorization/permissions (authz),
  API-to-API auth. Those are separate projects in this repo.

## 2. The flow (Authorization Code + PKCE)
```
Browser            RP (this app)                 IdP (Entra/Okta/…)
   │  GET /login        │                               │
   │───────────────────►│  build request:               │
   │                    │   client_id, redirect_uri,     │
   │                    │   scope, state, nonce,          │
   │                    │   code_challenge=S256(verifier) │
   │  302 to IdP authorize endpoint ───────────────────► │
   │  (user authenticates + consents at the IdP)         │
   │ ◄─── 302 back to redirect_uri?code=…&state=… ────── │
   │  GET /auth/callback│                               │
   │───────────────────►│  verify state matches session │
   │                    │  POST /token: code + code_verifier ───► │
   │                    │ ◄─── id_token + access_token ──────────│
   │                    │  validate id_token: signature (JWKS),  │
   │                    │   iss, aud, exp, nonce                  │
   │                    │  establish session cookie               │
   │ ◄── 302 / (logged in) ──│                               │
```

## 3. Key design decisions
| Decision | Why |
|---|---|
| **Use Authlib, not hand-rolled crypto** | Token parsing, JWKS handling, and signature validation are easy to get subtly wrong. The secure default is a vetted library. |
| **Authorization Code + PKCE** (not implicit) | The implicit flow is deprecated; it exposes tokens in the URL. Code+PKCE keeps tokens out of the browser/redirect and binds the code to this client. |
| **PKCE even with a confidential client** | Defense in depth: PKCE neutralizes authorization-code interception/injection regardless of client type. Recommended by the OAuth 2.0 Security BCP. |
| **OIDC discovery (`.well-known`)** | Endpoints + signing keys come from the issuer's metadata, so key rotation is automatic and there are no hardcoded URLs/keys. |
| **Store claims, not tokens, in the cookie** | The session cookie holds minimal identity claims. Raw tokens in a cookie widen the blast radius if it leaks. |
| **Fail closed** | Any validation error (bad `state`, bad `nonce`, bad signature, expired) returns 401 and establishes **no** session. |
| **Secrets from env only** | `client_secret` and the cookie signing key live in `.env` (gitignored), never in source. |

## 4. STRIDE threat model
| Threat | Vector | Mitigation in this design |
|---|---|---|
| **Spoofing** | Forged/replayed ID token | Signature verified against IdP **JWKS**; `iss`/`aud` checked; **nonce** binds the token to this login. |
| **Tampering** | Modified token or auth response | JWS signature validation; **PKCE** binds the code to the original request; **state** integrity. |
| **Repudiation** | "I didn't log in" | IdP holds the authoritative auth event/logs; `sub` recorded in session (extend with app-side audit logging). |
| **Information disclosure** | Token/secret leakage | Tokens never placed in URLs or the cookie; `client_secret` in env; **HttpOnly + Secure** cookie; HTTPS in prod. |
| **Denial of service** | JWKS/discovery fetch abuse | Authlib caches discovery + JWKS; add timeouts/rate limiting at the edge (noted as enhancement). |
| **Elevation of privilege** | Code interception / injection, CSRF on redirect | **PKCE** + **state**; exact-match `redirect_uri` registered at the IdP. |

## 5. Secure-by-design checklist
- [x] Authorization Code + **PKCE (S256)**
- [x] **state** (CSRF) and **nonce** (replay) enforced
- [x] ID-token validated: signature (JWKS), `iss`, `aud`, `exp`, `nonce`
- [x] Exact, pre-registered `redirect_uri`
- [x] Hardened library (Authlib); no hand-rolled token/crypto
- [x] Secrets in environment; **HttpOnly / SameSite=Lax / Secure-in-prod** session cookie
- [x] Fail-closed on every error path
- [ ] _Enhancements:_ refresh-token rotation + revocation, RP-initiated logout, negative-path tests

## 6. What a reviewer / director should take from this
The working code proves I can build the flow; this document proves I can **own the design** — pick
the right flow, justify each control, and articulate how the system behaves under attack and on
failure. That design-and-tradeoffs reasoning is the core of the security-architect role.
