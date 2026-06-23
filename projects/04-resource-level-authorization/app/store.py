"""
Tiny in-memory document store. Each document has an `owner` = the user's `sub`.

The owner field is what object-level authorization checks against. In a real app
this is the `WHERE owner_id = :current_user` (or equivalent) on every data access.
"""

_DOCS = {
    "a1": {"id": "a1", "owner": "alice", "title": "Alice — salary review", "body": "confidential"},
    "a2": {"id": "a2", "owner": "alice", "title": "Alice — 1:1 notes",      "body": "confidential"},
    "b1": {"id": "b1", "owner": "bob",   "title": "Bob — medical record",   "body": "confidential"},
}


def get(doc_id: str) -> dict | None:
    return _DOCS.get(doc_id)


def list_for(owner: str) -> list[dict]:
    return [d for d in _DOCS.values() if d["owner"] == owner]
