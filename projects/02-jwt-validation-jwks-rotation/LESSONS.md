# Lessons, Pitfalls & Non-Negotiables — JWT validation + JWKS rotation (resource server)

> Source notes for a future white paper. Captured while building and running a resource server
> that validates bearer JWTs, including a live key-rotation demo.

## 0. The model in one analogy (booth & bouncer)
- The **booth** (identity provider) hands out **tickets** (JWTs), each pressed with its private
  **stamp** (signing key).
- The **bouncer** (resource server / API) checks tickets against a **reference sheet** of public
  stamp-photos (**JWKS**). The bouncer can *recognize* a real stamp but can't *forge* one.
- **Two independent checks at the door:** (1) is the stamp recognized? (key/signature) and
  (2) is the ticket still in time? (`exp`). Both must pass.

## 1. Thesis (sharpened on the receiving side)
A token is trustworthy only after you **verify the signature and the `iss`/`aud`/`exp`** — never
because the bytes are readable or because a token is merely "present."

## 2. What was built
A FastAPI resource server (PyJWT) that requires `Authorization: Bearer <jwt>`, verifies the signature
against the IdP's **JWKS** (key matched by `kid`), **pins algorithms to RS256**, validates
`iss`/`aud`/`exp`/`iat`, and fails closed. Plus a dev-only issuer to mint tokens and force key
rotation. Verified live: no token→401, valid→200, tampered→401, post-rotation new-`kid`→200
(automatic JWKS refetch), fresh old-`kid` token→200 (graceful rotation).

## 3. Core lessons
1. **Readable ≠ trusted.** We decoded a token with no key and no password; trust lives only in the signature.
2. **The signature covers the exact bytes.** Change one character → verification fails (proven live).
3. **Algorithm pinning is mandatory.** The token's own `alg` is attacker-controlled; accepting it enables
   `alg=none` and HS/RS key-confusion. Pin `RS256` server-side; never read `alg` from the token.
4. **Validate AND require `iss`/`aud`/`exp`/`iat`.** A missing `aud`/`exp` means *invalid*, not
   "unconstrained." `aud` is what stops a token minted for another app being replayed at yours
   (confused deputy).
5. **JWKS = automatic key rotation.** An unknown `kid` triggers a refetch of the key set; new keys
   work instantly with no redeploy.
6. **Key validity and token expiry are independent checks.** A token can be rejected because its key
   was retired *or* because `exp` passed — different controls, different lifecycles. (This was the
   live "gotcha": an old token 401'd due to *expiry*, while a fresh token signed by the *same old key*
   still validated.)
7. **Graceful rotation:** publish old + new keys together; existing tokens keep working until they
   expire, so rotating keys never logs anyone out mid-session.

## 4. Non-negotiables (the "always")
- **Verify the signature** against JWKS by `kid`. Never skip verification / never decode-and-trust.
- **Pin algorithms** (RS256). Reject `alg=none`; never honor the token's own `alg`.
- **Require + validate** `iss`, `aud`, `exp` (and `iat`).
- **Fetch JWKS over HTTPS, cache it, refetch on unknown `kid`.**
- **Fail closed** with a generic `401`.
- **Short token TTLs;** bridge longer sessions with refresh tokens, not long-lived access tokens.

## 5. Common pitfalls / anti-patterns (what to flag in review)
- **Decode-and-go** — trusting an unverified JWT. The single most common token bug.
- **Not pinning `alg`** → `alg=none` / HS-RS key confusion.
- **Not checking `aud`/`iss`** → confused-deputy / cross-service token replay.
- **Treating a missing `exp`/`aud` as "no restriction."**
- **Hardcoding keys** instead of JWKS → breaks on rotation; or **never rotating** at all.
- **Unbounded JWKS refetch** on bogus `kid`s → DoS vector (cache + cooldown / rate-limit).
- **Long-lived tokens with no revocation strategy.**
- **Conflating expiry with key retirement when debugging** (the live gotcha) — they're separate checks.

## 6. Architectural decisions & tradeoffs
- **PyJWT (hardened) over hand-rolled JOSE** — signature/JWKS handling is where critical bugs hide.
- **JWKS cache lifespan + refetch-on-miss** — balances performance vs. picking up rotations promptly.
- **Token TTL tradeoff:** short (less exposure, more churn) vs. long (smoother, bigger stolen-token
  window); refresh tokens bridge the gap.
- **authn vs authz kept separate** — this project proves *who* the token is; *what they may do* is the
  next project.

## 7. How to demonstrate the understanding (for the paper / a reviewer)
- Show `valid→200` vs `tampered→401`; explain the signature is computed over the exact bytes.
- **Rotate keys live:** a new-`kid` token is accepted via automatic JWKS refetch, and a *fresh*
  old-`kid` token still validates — proving rotation is graceful.
- Explain the **two-independent-checks** model (key recognized **and** not expired) — narrating that
  gotcha correctly is the architect-level tell.

## 8. Open questions / next to explore
- **Authorization:** `scope` / roles — controlling *what* a valid user may do (the next project).
- Token revocation / introspection for opaque tokens.
- Refresh-token rotation + replay detection.
- JWKS refetch rate-limiting; reject tokens with no `kid`; pin acceptable `kid`s.
