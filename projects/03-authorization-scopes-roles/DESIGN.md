# DESIGN — Authorization (scopes & roles)

The "architect" half of project 03: how a resource server decides *what a verified identity may do*,
and why authorization is a separate layer from authentication.

## 1. Context & scope
- **Builds on project 02.** Authentication (verify the token) is reused unchanged; this project adds
  the **authorization** decision on top.
- **In scope:** endpoint-level access control via **scopes** and **roles**, deny-by-default.
- **Out of scope:** issuing tokens (`devissuer/` is a TEST aid), resource-level / row-level
  ownership checks, and full policy engines (noted as extensions).

## 2. authn vs authz (the whole point)
```
request ─► authenticate (verify token)              ── fail ─► 401  "who are you?"
              │ ok (identity known)
              ▼
           authorize (does this identity have the
           required scope / role for THIS action?)  ── fail ─► 403  "not allowed"
              │ ok
              ▼
           handler runs
```
- **401 Unauthorized** = authentication failed (no/invalid/expired token).
- **403 Forbidden** = authenticated successfully, but lacks the required permission.
Conflating them leaks information (a 403 on an unauthenticated request tells an attacker the token
was otherwise fine) and confuses clients.

## 3. Key design decisions
| Decision | Why |
|---|---|
| **Authorization is a distinct layer** | authn proves identity; authz applies policy. Different failures (401 vs 403), different reasons to change. |
| **Deny by default** | A protected route grants access only when the required scope/role is present. No requirement = explicitly open. |
| **Read permissions from the verified token** | `scope`/`roles` live in a signed token, so they're trustworthy *after verification* — and tamper-evident (project 02). |
| **Always enforce server-side** | Never trust a scope/role from a query param, header, or body — only from inside the verified token. |
| **Least privilege** | Routes require the *minimum* scope/role; `/api/profile` needs only authentication, `/api/admin` needs an explicit role. |

## 4. STRIDE threat model (authorization-specific)
| Threat | Vector | Mitigation |
|---|---|---|
| **Elevation of privilege** | Calling a privileged route without the right scope/role | Deny-by-default scope/role checks; least privilege per route. |
| **Spoofing / Tampering** | Forging or editing scope/role claims | Claims come from a signature-verified token (project 02); tampering breaks the signature. |
| **Information disclosure** | Returning 403 (or rich errors) to unauthenticated callers | Authenticate first → 401; only authenticated callers can receive 403; generic messages. |
| **Repudiation** | "I didn't perform that admin action" | `sub` from the verified token is recorded on privileged actions (pair with audit logging). |
| **Confused deputy** | Token for another audience used to gain access | `aud`/`iss` enforced upstream (project 02) before any authz check. |

## 5. Secure-by-design checklist
- [x] Authentication runs first (401), then authorization (403) — never merged
- [x] Deny by default; least-privilege per route
- [x] Scope (`reports:read`) and role (`admin`) gates
- [x] Permissions read only from the **verified** token, enforced server-side
- [ ] _Enhancements:_ resource-level ownership checks, policy engine (OPA/Cedar), full negative-path tests

## 6. What a reviewer / director should take from this
Projects 01–02 covered identity and token validity; this one shows I can reason about **access
control**: separating authn from authz, defaulting to deny, applying least privilege, and reading
authority only from a verified, tamper-evident source. Knowing *why* a 403 must come after a 401 —
and never instead of it — is exactly the kind of distinction an auth architect is expected to own.
