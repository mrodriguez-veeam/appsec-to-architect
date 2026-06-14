"""
Authorization layer — what a *verified* identity is allowed to do.

Authentication (verifier.py) answers "who are you?" and fails with **401**.
Authorization (here) answers "are you allowed to do THIS?" and fails with **403**.
Keeping them distinct is the whole lesson of this project.

Design choices:
  - Deny by default: a route with no requirement is open; a protected route
    grants access ONLY if the required scope/role is present.
  - Trust the claim because it's inside a *signed, verified* token — but always
    ENFORCE server-side. Never trust a scope/role the client supplies elsewhere
    (query string, header, request body).
"""
from fastapi import Depends, Header, HTTPException

from .verifier import TokenError, TokenVerifier


def make_auth(verifier: TokenVerifier):
    """Build FastAPI dependencies bound to a configured verifier."""

    def claims(authorization: str = Header(default="")) -> dict:
        """Authentication: extract + verify the bearer token, else 401."""
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")
        try:
            return verifier.verify(token)
        except TokenError:
            raise HTTPException(status_code=401, detail="Invalid or expired token")

    def _token_scopes(c: dict) -> set[str]:
        # OAuth puts scopes in a space-delimited `scope` string (sometimes `scp`).
        raw = c.get("scope") or c.get("scp") or ""
        if isinstance(raw, list):
            return set(raw)
        return set(raw.split())

    def require_scopes(*needed: str):
        """Authorization: require ALL of these scopes, else 403 (authn first → 401)."""
        def dep(c: dict = Depends(claims)) -> dict:
            have = _token_scopes(c)
            missing = [s for s in needed if s not in have]
            if missing:
                raise HTTPException(
                    status_code=403,
                    detail=f"Insufficient scope: missing {missing}",
                )
            return c
        return dep

    def require_role(role: str):
        """Authorization: require this role in the `roles` claim, else 403."""
        def dep(c: dict = Depends(claims)) -> dict:
            roles = c.get("roles") or []
            if isinstance(roles, str):
                roles = roles.split()
            if role not in roles:
                raise HTTPException(status_code=403, detail=f"Requires role '{role}'")
            return c
        return dep

    return claims, require_scopes, require_role
