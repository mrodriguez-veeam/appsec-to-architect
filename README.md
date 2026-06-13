# AppSec → Security Architect

Personal notes, resources, and **hands-on projects** for my career development in security.

I'm deliberately closing the gap between AppSec engineering and **security architecture**,
with a current focus on **authentication** — building real, runnable code and documenting the
design and threat-model thinking behind each project.

Every project here pairs **working code** with a **`DESIGN.md`** (architecture + STRIDE threat model
+ key decisions). The code shows I can build; the design docs show I can architect.

## Projects

| # | Project | Focus | Status |
|---|---------|-------|--------|
| 01 | [OAuth2 / OIDC — Authorization Code + PKCE](projects/01-oauth2-oidc-pkce/) | OIDC relying-party login done securely (PKCE, state, nonce, ID-token validation) | 🟡 In progress |

_Status key: 🟢 complete · 🟡 in progress · ⚪ planned_

## Planned next

- JWT validation + JWKS key rotation
- Session management (secure cookies, refresh-token rotation, revocation)
- WebAuthn / passkeys (FIDO2)
- Service-to-service auth (mTLS / token exchange) + policy-based authorization

## How to read this repo

Start with a project's `README.md` (what it is, how to run it), then its `DESIGN.md`
(why it's built that way, and how it fails safely).
