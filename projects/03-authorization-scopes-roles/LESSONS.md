# Lessons, Pitfalls & Non-Negotiables — Authorization (scopes & roles)

> Source notes for a future white paper. Captured after building and walking through a resource
> server that enforces access control on top of token authentication.

## 0. The model in one analogy (a building with rooms)
- A valid ticket (a verified JWT) gets you **into the building** = authentication (project 02).
- Inside, different **rooms** need different passes:
  - **VIP room** = a **wristband** (a *scope*, e.g. `reports:read`) — *what actions* the token may perform.
  - **Staff-only room** = a **badge** (a *role*, e.g. `admin`) — *what kind of user* you are.
- The **front-door guard** asks "who are you?" → **401** if no/invalid ticket.
  The **room guards** ask "are you allowed in *here*?" → **403** if you're in the building but lack the pass.

## 1. Thesis
**`401` ≠ `403`.** Authentication and authorization are different questions, fail differently, and
must run **in that order**: prove identity first, *then* apply policy.

## 2. What was built
A FastAPI resource server with **deny-by-default** scope/role checks layered on project 02's verifier.
Three routes of increasing privilege — `/api/profile` (any valid token), `/api/reports`
(scope `reports:read`), `/api/admin` (role `admin`). Verified live: no token→`401`,
valid-but-no-scope→`403`, valid+scope→`200`, valid+role→`200`, and a scope did **not** open a
role-gated room.

## 3. Core lessons (felt during the walkthrough)
1. **`401` vs `403` — the one to internalize.** Same endpoint, three answers depending only on the token:
   - **`401` Unauthorized** = "I don't know who you are" (no/invalid token) → *authentication*.
   - **`403` Forbidden** = "I know exactly who you are — you're not allowed to do *this*" → *authorization*.
2. **Authenticate first, then authorize.** A `403` only makes sense once identity is established;
   never return `403` to an *unauthenticated* caller (it leaks that the token was otherwise fine).
3. **Scopes vs roles are different tools:**
   - **scope** = *what actions* a token may perform (`reports:read`) — the wristband.
   - **role** = *what kind of principal* the user is (`admin`) — the badge.
   A VIP wristband does **not** open the staff room. Real systems use both; choose deliberately per gate.
4. **Deny by default.** A protected route grants access only when the required pass is present; the
   default answer is "no."
5. **Trust the claim because it's verified — but enforce server-side.** Permissions live *inside the
   signed token* (tamper-evident, project 02), so they're trustworthy after verification. Never read a
   scope/role from a client-supplied header, query string, or body.
6. **Least privilege.** `/api/profile` needs only authentication; privileged rooms require an explicit,
   minimal pass — nothing gets more access than it needs.

## 4. Non-negotiables (the "always")
- **Authenticate (401) before authorizing (403).** Never merge them or reverse the order.
- **Deny by default;** grant only on an explicit, matching scope/role.
- **Read authority ONLY from the verified token,** and enforce it on the server.
- **Least privilege** per route.
- **Don't leak:** generic messages; never `403` an unauthenticated request.

## 5. Common pitfalls / anti-patterns (what to flag in review)
- Returning **`403` where `401` belongs** (or vice-versa) — confuses clients and leaks token validity.
- **Trusting a scope/role from outside the token** (query param, header, body).
- **Default-allow** routes — forgetting to protect a newly added endpoint.
- **Over-broad scopes/roles** ("everyone is admin") — privilege creep.
- **Checking authorization before authentication.**
- **Endpoint-only checks** when the data needs **ownership** checks (alice reading bob's record) —
  the next depth level.

## 6. Architectural decisions & tradeoffs
- **Authorization as a distinct layer** over the reused verifier — separation of concerns (authn vs authz).
- **Inline scope/role checks now**, a **policy engine (OPA/Cedar)** when rules grow — simplicity vs.
  centralized, auditable policy.
- **Scopes (token/OAuth-level) vs roles (identity-level)** — which to gate on is a deliberate design call.
- **Endpoint-level vs resource-level** authorization — this project does endpoint-level; row/owner-level
  is the next step.

## 7. How to demonstrate the understanding (for the paper / a reviewer)
- Hit one endpoint three ways: no token (`401`), valid token without the scope (`403`), valid token
  with the scope (`200`).
- Show a **scope (wristband) failing a role-gated route** (`403`) — proving scope ≠ role.
- Articulate **why `403` must follow `401`, never replace it.**

## 8. Open questions / next to explore
- **Resource/row-level authorization** (ownership), not just endpoint-level.
- **Policy engine** (OPA / Cedar) — externalizing authz rules from application code.
- **Scope design:** granularity, hierarchy, scope→permission mapping.
- Token-carried authz vs a centralized authorization service.
