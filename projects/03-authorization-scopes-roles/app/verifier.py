"""
JWT verifier (authentication half) — same hardened core as project 02.

Proves a bearer token is authentic and meant for us: signature via JWKS (key by
`kid`), algorithms PINNED to RS256, and `iss`/`aud`/`exp`/`iat` validated+required.
Authorization (what the verified identity may DO) is layered on top in authz.py.
"""
import jwt
from jwt import PyJWKClient


class TokenError(Exception):
    """Token failed an authenticity/claim check (→ 401, fail closed)."""


class TokenVerifier:
    def __init__(self, jwks_url: str, issuer: str, audience: str,
                 algorithms: tuple[str, ...] = ("RS256",)):
        self.issuer = issuer
        self.audience = audience
        self.algorithms = list(algorithms)
        self._jwks = PyJWKClient(jwks_url, cache_keys=True, lifespan=300)

    def verify(self, token: str) -> dict:
        try:
            signing_key = self._jwks.get_signing_key_from_jwt(token)
            return jwt.decode(
                token,
                signing_key.key,
                algorithms=self.algorithms,
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "iss", "aud"]},
            )
        except jwt.PyJWTError as exc:
            raise TokenError(str(exc)) from exc
