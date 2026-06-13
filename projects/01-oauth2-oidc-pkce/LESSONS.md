# Lessons, Pitfalls & Non-Negotiables — OIDC Authorization Code + PKCE

> Source notes for a future white paper. Captured while building and running a working
> OpenID Connect relying party (FastAPI + Authlib) and authenticating end-to-end against Entra ID.
> Written to be reused/expanded later — hence the "why," not just the "what."

## 1. The one-sentence thesis
**Anyone can *read* a token; trust comes only from *verification*.** A JWT is just base64url —
readable by anyone. Its security value comes entirely from validating the signature and the
`iss` / `aud` / `exp` / `nonce` claims *before* acting on it. Everything below is a corollary.

## 2. What was built (context for the paper)
A relying party (the app that logs users in) implementing the **Authorization Code flow with PKCE**
against an OIDC provider. The app delegates authentication to the IdP, receives an **authorization
code** in the browser, exchanges it **server-side** for tokens, validates the **ID token**, and
establishes a session. Verified live: the `/authorize` request carried PKCE/state/nonce, and the
returned ID token validated and decoded to the expected claims.

## 3. Core lessons
1. **The browser only ever holds a one-time code — never the tokens.** In the code flow the
   code→token exchange happens server-to-server. Tokens never touch the browser, the URL, or
   client-side JS. (The deprecated *implicit* flow returned tokens in the URL fragment — that's the
   anti-pattern this flow exists to kill.)
2. **Four request-side controls do the heavy lifting**, and they're visible in the real redirect:
   - **PKCE** (`code_challenge` + `code_challenge_method=S256`) — binds the code to this client;
     neutralizes code interception/injection.
   - **`state`** — CSRF protection on the redirect back.
   - **`nonce`** — replay protection; binds the issued ID token to *this* login attempt.
   - **Exact, pre-registered `redirect_uri`** — no wildcards, no open redirects.
3. **ID-token validation is the real work** (the IdP/library does it; you must not skip it):
   signature via the header's `kid` → the IdP's **JWKS**, then `iss`, `aud`, `exp`, and `nonce`.
4. **Discovery + JWKS give you automatic key rotation.** Endpoints and signing keys come from
   `/.well-known/openid-configuration`; when the IdP rotates keys the `kid` changes and the RP
   fetches the new key — nothing is hardcoded.
5. **Identify users by `sub`, not `email`.** `sub` is stable and opaque; emails get reassigned.
   (Entra also exposes `oid` — stable tenant-wide — vs `sub` which is per-application.)
6. **Federation is visible in the token.** An `idp` claim pointing at a different tenant than `iss`
   means the user is a federated/guest (B2B) identity — worth recognizing when reasoning about trust.

## 4. Non-negotiables (the "always")
- Use **Authorization Code + PKCE**. Never the implicit flow.
- **Always validate** the ID token: signature (JWKS), `iss`, `aud`, `exp`, and `nonce`.
- **Never trust a JWT because you can read it.** Decoding ≠ verifying.
- **Secrets in a secret store / env**, never in source or client-side.
- **Tokens stay server-side.** Never in `localStorage`, never in a JS-readable cookie, never in a URL.
- **Session cookie:** `HttpOnly`, `SameSite` (Lax for redirect login), `Secure` over HTTPS.
- **Exact-match `redirect_uri`.** No wildcards.
- **Fail closed.** Any validation error → no session, generic error to the user.

## 5. Common pitfalls / anti-patterns (what to flag in review)
- Using the **implicit flow** or putting tokens in the URL fragment.
- **Not validating `aud`** → token-substitution / confused-deputy (accepting a token minted for a
  different app).
- **Skipping `nonce`** → replay of a stolen/old ID token.
- **Trusting an unverified JWT** (decode-and-go) — the single most common token bug.
- **Storing tokens in `localStorage`** or a JS-readable cookie → XSS-stealable.
- **Keying users on `email`** instead of `sub`.
- **Wildcard / loosely-matched `redirect_uri`** → open redirect / code theft.
- **Logging raw tokens.** (Modeled deliberately in this project as a *default-off, dev-only* flag —
  shipping it on is itself a finding. Demonstrates the principle by making the misuse explicit.)
- **Hardcoding endpoints/keys** instead of using discovery + JWKS → breaks on key rotation.

## 6. Architectural decisions & tradeoffs (made here)
- **Use a hardened library (Authlib), don't hand-roll crypto/token handling.** The secure default;
  hand-rolled JOSE/JWKS is where subtle, high-severity bugs live.
- **Store minimal claims, not raw tokens, in the session.** Smaller blast radius if the cookie leaks.
- **PKCE even with a confidential client.** Defense in depth, per the OAuth 2.0 Security BCP.
- *Out of scope here (and why):* running an IdP, authorization/permissions (authz), and API-to-API
  auth are separate concerns → separate projects, so each stays focused.

## 7. Language portability — what carries over, what's just plumbing
OIDC/OAuth2 is a **protocol standard (RFCs), not a feature of any language**. So the understanding
is ~90% portable; only the SDK and syntax change.

**Identical in every language (the durable asset):** Authorization Code + PKCE; `state`/`nonce`/exact
`redirect_uri`; ID-token validation (signature via `kid`→JWKS, `iss`, `aud`, `exp`, `nonce`); tokens
stay server-side while the browser holds only a one-time code; identify users by `sub`; fail closed;
`HttpOnly`/`SameSite`/`Secure` cookies; secrets out of code. Decode an ID token from a .NET, Go, or
Node app and you read the *same* claims.

**Changes per stack (disposable plumbing):** just the library + framework.

| Stack | OIDC library (the "Authlib" slot) | Web framework |
|-------|-----------------------------------|---------------|
| Python | Authlib / oauthlib | FastAPI / Flask / Django |
| Node / TypeScript | `openid-client`, Passport | Express / Nest |
| .NET | Microsoft.Identity.Web (MSAL) | ASP.NET Core |
| Java | Spring Security OAuth, Nimbus | Spring Boot |
| Go | `coreos/go-oidc` + `x/oauth2` | net/http / Gin |

**Carry-over caution (a non-negotiable in any language):** don't assume the library validates
everything by default — some skip `nonce` or `aud` unless enabled. The validation *checklist* is
universal; blind trust in the SDK is not.

**Not language, but watch it:** some details are **IdP-specific** (e.g. Entra's `oid`/`tid`, the v2.0
endpoint) rather than language-specific; and **client type** matters more than language — public
clients (SPA/mobile, no secret) make PKCE mandatory, confidential (server) clients add a secret.

**Architect framing:** own the **protocol and the threat model**; treat the SDK as an implementation
detail. Learn the flow once and it transfers to every stack — porting is just "find this ecosystem's
`openid-client` and map the concepts."

## 8. How to demonstrate the understanding (for the paper / a reviewer)
- Show the real `/authorize` redirect and name each parameter's job (PKCE/state/nonce).
- Decode an ID token and walk `aud`/`iss`/`exp`/`nonce`; show the `nonce` matches the request.
- State the trust boundary out loud: *"the browser only handles a one-time code; tokens and
  validation live server-side."* That sentence is the architect-level tell.

## 9. Open questions / next to explore
- Refresh-token rotation + revocation (and detecting refresh-token replay).
- RP-initiated logout and end-session semantics across IdPs.
- `authz` (what a user can do) vs `authn` (who they are) — the next project.
- Service-to-service auth: mTLS / token exchange (RFC 8693).
