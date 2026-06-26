# Lessons, Pitfalls & Non-Negotiables — Resource-level authorization (IDOR / BOLA)

> Source notes for a future white paper. Captured after building and walking through a resource
> server that enforces per-object ownership — and demonstrating the IDOR leak live.

## 0. The model in one analogy (a records room with personal files)
- A valid badge gets you **into the records room** = authentication + endpoint authorization (projects 02–03).
- Each **file has a name on it.** This project answers one question: *does the name on the file match
  the person asking?*
- **Good clerk** (secure endpoint) checks the name → refuses non-owners (`403`).
  **Bad clerk** (insecure endpoint) hands over any file you name → **leak**.

## 1. Thesis
**Being allowed to call an endpoint is not the same as being allowed to touch a specific object.**
The last and most-missed gate is **per-object ownership** — and skipping it is **Broken Object Level
Authorization (BOLA / IDOR)**, OWASP API1:2023, the #1 API risk.

## 2. What was built
A FastAPI resource server exposing the same read two ways — a deliberately **insecure** route (no
ownership check) and a **secure** one (`owner == caller.sub`, or `admin`). Seed data: alice owns
`a1`/`a2`, bob owns `b1`. Verified live: alice→her own (`200`), alice→bob's secure (`403`),
alice→bob's **insecure (`200`, returned bob's record)**, admin→bob's secure (`200`).

## 3. Core lessons (felt during the walkthrough)
1. **Endpoint access ≠ object access.** Alice was authenticated *and* allowed to call the route, yet
   the secure endpoint still refused Bob's file (`403`) while the insecure one leaked it (`200`).
   A route-level check cannot know *which object* you asked for.
2. **The leak is one missing line.** The only difference between secure and insecure was the ownership
   comparison. BOLA is an **omission** bug — invisible unless you specifically test "can user A reach
   user B's object?"
3. **Authentication always precedes authorization** (the live detour). When Alice's badge expired she
   got a `401`, never reaching the ownership check — proving the order: *valid identity first, then
   per-object permission*. (`401` = bad/expired badge; `403` = good badge, not your file.)
4. **Identity for the check comes from the verified token (`sub`)** — never from an id in the request.
5. **Scope the data access to the current user.** In SQL terms: `WHERE id = :id AND owner_id = :me` —
   don't fetch by id and then trust the route to have protected it.
6. **Legitimate cross-user access is an explicit, role-gated decision** (admin), not an unchecked path.
   Same outcome as the leak (admin sees Bob's file), opposite posture: a *decision* vs. an *omission*.

## 4. Non-negotiables (the "always")
- **Check ownership on EVERY object access** — reads *and* writes/deletes.
- **Derive the owner identity from the verified token,** and enforce on the server.
- **Scope queries to the current user** (`WHERE owner_id = :me`), don't fetch-by-id-then-return.
- **Centralize the check** (shared dependency / decorator / row-level scoping) so a new endpoint
  can't silently forget it.
- **Admin / cross-user access via an explicit role only.**

## 5. Common pitfalls / anti-patterns (what to flag in review)
- **Fetch-by-id then return** with no owner check — the classic IDOR.
- Checking only the **endpoint/role** and assuming it covers the **object**.
- **Trusting an owner id from the request** (body/param/header) instead of the token.
- **Sequential / guessable ids** + no owner check → trivial enumeration of everyone's data.
- **Object checks on read but not on write/delete.**
- A `403` that **reveals an object exists** when existence itself is sensitive (use `404`).

## 6. Architectural decisions & tradeoffs
- **`403` vs `404` for non-owned objects:** `403` is clearest; `404` *hides existence* (defeats
  id-enumeration). Choose by how sensitive mere existence is.
- **Centralized check vs per-endpoint:** centralize (dependency, decorator, or DB row-level security)
  because BOLA is almost always a *forgotten* check on one new endpoint.
- **Endpoint-level (03) vs object-level (04):** not either/or — you need both gates.
- **Admin override via role vs. a separate admin API:** explicit and auditable either way; never a
  bypass path.

## 7. How to demonstrate the understanding (for the paper / a reviewer)
- One object, three results: owner (`200`), non-owner on the secure route (`403`), non-owner on the
  insecure route (`200` — and it returns the *victim's actual record*).
- Point out the difference is a single ownership check — an omission, not a config.
- Note **authn precedes authz** (the expired-badge `401`), and that admin access is an explicit role
  decision, not the same as the leak.

## 8. Open questions / next to explore
- Ownership checks on **write/delete** and on **nested/related** resources.
- **Centralized authorization:** policy engine (OPA/Cedar) or database **row-level security (RLS)**.
- **Field-level** authorization (which *fields* of an object a user may see).
- **Audit logging** of cross-user (admin) access.
