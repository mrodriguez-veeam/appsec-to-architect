# DESIGN — Resource server: JWT validation + JWKS rotation

The "architect" half of project 02: how a resource server decides whether to trust an incoming
token, the failure modes, and the design choices.

## 1. Context & scope
- **Role implemented:** the **Resource Server** — it protects an API and must verify access tokens
  minted by a separate IdP. It does **not** log users in (that's project 01) and does **not** decide
  *permissions* (authz) — only *authenticity* (authn): is this token real and meant for me?
- **In scope:** bearer-JWT verification, JWKS retrieval + key rotation, fail-closed rejection.
- **Out of scope:** issuing tokens (the `devissuer/` is a TEST aid only), authorization/roles.

## 2. The validation pipeline (every request)
```
Authorization: Bearer <jwt>
        │
        ▼
 parse header → read `kid`
        │
        ▼
 find key `kid` in cached JWKS ──(miss)──► refetch JWKS from jwks_uri ──(still miss)──► 401
        │ (hit)
        ▼
 verify signature with PINNED alg (RS256)      ← blocks alg=none / HS-RS confusion
        │
        ▼
 validate claims: iss == expected, aud == this API, exp not passed, iat/exp present
        │ (any failure → 401, generic message)
        ▼
 trusted claims → handler runs
```

## 3. Key design decisions
| Decision | Why |
|---|---|
| **Pin algorithms to `RS256`** | The token header's `alg` is attacker-controlled. Accepting it enables `alg=none` (no signature) and **HS/RS confusion** (verifying an RS token as HS using the *public* key as the HMAC secret). Pin server-side; never read `alg` from the token. |
| **Verify against JWKS by `kid`** | Asymmetric: the IdP signs with its private key; we verify with the matching public key fetched from the IdP's JWKS. No shared secret to leak. |
| **Cache JWKS + refetch on unknown `kid`** | Performance (don't fetch per request) *and* graceful rotation: a new `kid` triggers a refresh; old keys stay valid until their tokens expire. |
| **Require `iss` / `aud` / `exp` / `iat`** | A token with no `aud`/`exp` must be rejected, not treated as "no constraint." Missing-claim = invalid. |
| **Use PyJWT (hardened), not hand-rolled JOSE** | Signature/JWKS handling is where subtle, critical bugs live. |
| **Fail closed, generic errors** | Any verification failure → 401 with a non-revealing message; details stay in server logs. |

## 4. STRIDE threat model
| Threat | Vector | Mitigation |
|---|---|---|
| **Spoofing** | Forged token / `alg=none` / HS-RS confusion | Signature required; **algorithms pinned to RS256**; verified against JWKS public key. |
| **Tampering** | Modified header/payload | Any change breaks the signature → rejected. |
| **Repudiation** | "I didn't call that" | `sub` from a verified token identifies the caller; pair with request logging. |
| **Information disclosure** | Verbose errors leak why a token failed | Generic 401; specifics only server-side. |
| **Denial of service** | Forcing JWKS refetches (bogus `kid`s) | JWKS cached with a lifespan; add a refetch cooldown / rate limiting at the edge (noted). |
| **Elevation of privilege** | Token minted for another audience reused here (confused deputy) | **`aud` checked** == this API; **`iss`** checked == expected issuer. |
| **Expiry/replay** | Old or stolen token reused | `exp` enforced; short token lifetimes; (refresh-token replay handled upstream). |

## 5. Secure-by-design checklist
- [x] Signature verified against JWKS key matching the token `kid`
- [x] **Algorithms pinned** (RS256) — `alg=none` / HS-RS confusion blocked
- [x] `iss`, `aud`, `exp`, `iat` validated and **required**
- [x] JWKS cached + auto-refetch on unknown `kid` (graceful rotation)
- [x] Fail closed; generic 401
- [ ] _Enhancements:_ authz on `scope`/roles, reject missing `kid`, refetch rate-limit, negative-path tests

## 6. What a reviewer / director should take from this
Project 01 proved I can stand up a login; project 02 proves I understand the **trust boundary on the
receiving side** — why algorithm pinning matters, what `aud`/`iss`/`exp` actually defend against, and
how key rotation stays graceful. Being able to enumerate the token-validation failure modes (and
demonstrate rotation live) is core resource-server architecture.
