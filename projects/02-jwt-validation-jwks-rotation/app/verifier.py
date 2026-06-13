"""
JWT access-token verifier — the secure core of a "resource server".

Before trusting ANY claim in an incoming bearer token, prove the token is:
  1. authentic   — signed by the IdP (signature checked against the JWKS key whose
                   `kid` matches the token header), and
  2. for us      — `aud` is our API, `iss` is the expected issuer, not expired.

Uses PyJWT (hardened) for the crypto — we never hand-roll JOSE.

Non-negotiables enforced here:
  - algorithms are PINNED (RS256) — blocks `alg=none` and HS/RS algorithm confusion
  - signature verified against the JWKS key matching the token's `kid`
  - iss / aud / exp / iat validated, and those claims are REQUIRED to be present
  - JWKS is cached and auto-refetched on an unknown `kid` (graceful key rotation),
    then fails closed if the key still can't be found
"""
import jwt
from jwt import PyJWKClient


class TokenError(Exception):
    """Raised when a token fails any authenticity/claim check (fail closed)."""


class TokenVerifier:
    def __init__(self, jwks_url: str, issuer: str, audience: str,
                 algorithms: tuple[str, ...] = ("RS256",)):
        self.issuer = issuer
        self.audience = audience
        self.algorithms = list(algorithms)
        # PyJWKClient fetches + caches the JWKS and, on seeing a `kid` it doesn't
        # have cached, refetches — which is exactly what happens after the IdP
        # rotates signing keys. lifespan caps how long a cached key set is reused.
        self._jwks = PyJWKClient(jwks_url, cache_keys=True, lifespan=300)

    def verify(self, token: str) -> dict:
        try:
            # Resolve the signing key by the token's `kid` (refetch on cache miss).
            signing_key = self._jwks.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=self.algorithms,   # PINNED — never trust the token's own `alg`
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "iss", "aud"]},
            )
            return claims
        except jwt.PyJWTError as exc:
            # Fail closed: any signature / claim / rotation failure -> rejected.
            raise TokenError(str(exc)) from exc
