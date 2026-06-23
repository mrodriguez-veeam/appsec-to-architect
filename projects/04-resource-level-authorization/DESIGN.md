# DESIGN — Resource-level authorization (IDOR / BOLA)

The "architect" half of project 04: why endpoint-level authorization is not enough, and how to stop
the most common (and highest-impact) API vulnerability.

## 1. Context & scope
- **Builds on 02 (authn) and 03 (endpoint authz).** Reuses the verifier unchanged.
- **In scope:** per-object **ownership** checks on data access; the vulnerable vs. secure contrast.
- **Out of scope:** write/delete object checks (same idea), centralized policy engines (extensions).

## 2. The gap: route access ≠ object access
```
Project 03 asked:  "May this identity call GET /api/documents/{id}?"      (endpoint-level)
Project 04 asks:   "May this identity read THIS document #{id}?"          (object-level)
```
Both `/api/insecure/...` and `/api/documents/...` pass the *endpoint* check (any valid token). Only
the secure one also asks the *object* question — `doc.owner == caller.sub`. Skipping that second
question is **Broken Object Level Authorization (OWASP API1:2023)** / **IDOR**.

## 3. The vulnerable pattern (what to catch in review)
```python
doc = store.get(doc_id)      # fetch by id from the URL
return doc                   # BUG: returns it to anyone authenticated
```
The fix is one comparison on every data access:
```python
if doc.owner != caller.sub and not caller.is_admin:
    raise Forbidden
```
In SQL terms: **always scope the query to the current user** — `WHERE id = :id AND owner_id = :me` —
rather than fetching by id alone and trusting the route.

## 4. Key design decisions
| Decision | Why |
|---|---|
| **Check ownership on every object access** | Endpoint authz can't know *which* row you asked for. The owner check is the only thing standing between users' data. |
| **Derive identity from the verified token (`sub`)** | The owner comparison must use the authenticated `sub`, never an id supplied in the request. |
| **Admin override via role** | Legitimate cross-user access (support/admin) goes through an explicit role check, not a backdoor. |
| **Centralize the check (ideal)** | A shared dependency/decorator means no new endpoint can silently forget it (BOLA is usually an *omission* bug). |
| **`403` vs `404` for non-owned** | `403` is clearest for teaching. **Hardened choice: return `404`** so you don't even confirm the object exists, defeating id-enumeration. Use `404` when existence itself is sensitive. |

## 5. STRIDE threat model
| Threat | Vector | Mitigation |
|---|---|---|
| **Information disclosure** | Read another user's object by changing the id (IDOR) | Owner check (`owner == sub`) on every access; optionally `404` to hide existence. |
| **Elevation of privilege** | Acting on objects you don't own | Same ownership gate on write/delete (extension); admin via explicit role only. |
| **Spoofing** | Claiming to be the owner | Identity comes from the *verified* token `sub` (projects 02), not request input. |
| **Enumeration** | Probing sequential/guessable ids | `404`-not-`403` for non-owned; non-sequential ids; rate limiting (noted). |

## 6. Secure-by-design checklist
- [x] Every object read checks `owner == authenticated sub`
- [x] Identity taken from the verified token, never from request parameters
- [x] Admin override is an explicit role check, not an exception path
- [x] Vulnerable route is clearly labeled and isolated (teaching only)
- [ ] _Enhancements:_ ownership on write/delete, centralized check, `404`-hide-existence, enumeration controls

## 7. What a reviewer / director should take from this
This is the vulnerability class I most need to catch in real code review. Projects 01–03 established
identity, token validity, and route access; this one shows I understand that **the last and most-missed
gate is per-object ownership** — and can both *spot the omission* and *state the fix* (scope the query
to the current user; centralize so it can't be forgotten). That's BOLA, the #1 API risk, owned end to end.
