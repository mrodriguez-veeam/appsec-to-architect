"""
OIDC Relying Party — Authorization Code flow with PKCE.

Demonstrates the *correct, secure* way for an application (a "relying party") to
authenticate users against any OpenID Connect provider — Entra ID, Okta, Auth0,
Google, Keycloak, etc. It uses Authlib (a hardened OAuth/OIDC library) instead of
hand-rolling crypto, and turns on every relevant protection:

  - PKCE (S256)          protects the authorization code against interception
  - state                CSRF protection on the redirect back to us
  - nonce                replay protection; binds the ID token to THIS login
  - OIDC discovery       issuer / JWKS / endpoints read from .well-known
  - ID token validation  signature (via JWKS), iss, aud, exp, nonce  (Authlib does this)
  - secure session cookie HttpOnly, SameSite=Lax, Secure in production

See README.md to run it. Security rationale and threat model are in DESIGN.md.
"""
import logging
import os

from authlib.integrations.starlette_client import OAuth, OAuthError
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

load_dotenv()


def _require(name: str) -> str:
    """Fail fast (and closed) if a required secret/config value is missing."""
    val = os.environ.get(name)
    if not val:
        raise RuntimeError(f"Missing required environment variable: {name} (see .env.example)")
    return val


# --- Configuration: every secret comes from the environment, never the source. ---
ISSUER         = _require("OIDC_ISSUER")          # e.g. https://login.microsoftonline.com/<tenant>/v2.0
CLIENT_ID      = _require("OIDC_CLIENT_ID")
CLIENT_SECRET  = _require("OIDC_CLIENT_SECRET")
SESSION_SECRET = _require("SESSION_SECRET")       # random 32+ byte string
REDIRECT_URI   = os.environ.get("OIDC_REDIRECT_URI", "http://localhost:8000/auth/callback")
SCOPES         = os.environ.get("OIDC_SCOPES", "openid profile email")
COOKIE_SECURE  = os.environ.get("COOKIE_SECURE", "false").lower() == "true"  # True behind HTTPS

# DEV-ONLY learning aid. When true, the raw ID token (a JWT) is written to the
# server log on each login so you can decode it yourself (see decode_jwt.py).
# Default OFF. NEVER enable outside local dev: raw tokens in logs are sensitive
# credentials and a real finding if shipped.
DEV_LOG_ID_TOKEN = os.environ.get("DEV_LOG_ID_TOKEN", "false").lower() == "true"

logger = logging.getLogger("oidc-rp")

app = FastAPI(title="OIDC RP — Authorization Code + PKCE")

# Signed, HttpOnly session cookie. It only holds the transient login state
# (PKCE verifier / state / nonce) and, after login, a few user claims —
# never raw access/ID tokens.
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    https_only=COOKIE_SECURE,   # Secure flag in production (HTTPS)
    same_site="lax",            # Lax is correct for a top-level redirect login
)

oauth = OAuth()
oauth.register(
    name="oidc",
    server_metadata_url=f"{ISSUER}/.well-known/openid-configuration",  # OIDC discovery
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    client_kwargs={
        "scope": SCOPES,
        "code_challenge_method": "S256",   # <-- this single line turns on PKCE
    },
)


@app.get("/")
async def home(request: Request):
    user = request.session.get("user")
    if user:
        who = user.get("email") or user.get("name") or user.get("sub")
        return HTMLResponse(
            f"<h3>Signed in as {who}</h3>"
            '<p><a href="/whoami">/whoami (decoded ID-token claims)</a> &middot; '
            '<a href="/me">/me (json)</a> &middot; <a href="/logout">logout</a></p>'
        )
    return HTMLResponse('<h3>Not signed in</h3><p><a href="/login">Log in with OIDC</a></p>')


@app.get("/login")
async def login(request: Request):
    # Authlib generates and stores state, nonce, and the PKCE code_verifier in the
    # session, and sends code_challenge to the IdP. We never build the URL by hand.
    return await oauth.oidc.authorize_redirect(request, REDIRECT_URI)


@app.get("/auth/callback")
async def callback(request: Request):
    try:
        # Validates state (CSRF), exchanges code + code_verifier (PKCE) for tokens,
        # then validates the ID token: signature via JWKS, iss, aud, exp, and nonce.
        token = await oauth.oidc.authorize_access_token(request)
    except OAuthError as exc:
        # Fail closed: never establish a session on any validation error.
        raise HTTPException(status_code=401, detail=f"Authentication failed: {exc.error}")

    # DEV-ONLY: log the raw ID token so you can decode it the "real" way:
    #   python decode_jwt.py "<paste the token from the log>"
    # Gated off by default; the token never goes to the browser or the cookie.
    if DEV_LOG_ID_TOKEN:
        logger.warning(
            "[DEV] raw id_token (decode locally with decode_jwt.py; never enable in prod):\n%s",
            token.get("id_token", "(no id_token in response)"),
        )

    claims = token.get("userinfo") or {}
    # Store only what the app needs. Do NOT put raw tokens in the cookie.
    request.session["user"] = {
        "sub": claims.get("sub"),
        "email": claims.get("email"),
        "name": claims.get("name"),
    }
    # LEARNING ONLY: also stash the full *validated* ID-token claims so the
    # /whoami debug view can show what the token actually contained. These are
    # identity claims (not the raw token); a real app would not need to keep them.
    request.session["claims"] = dict(claims)
    return RedirectResponse(url="/")


@app.get("/me")
async def me(request: Request):
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return JSONResponse(user)


# Maps the security-critical ID-token claims to a plain-English explanation.
_CLAIM_NOTES = {
    "iss":   "Issuer — who minted this token (must be your tenant). Validated.",
    "aud":   "Audience — who it was minted FOR (must be your client_id). Validated.",
    "exp":   "Expiry (unix time) — token is rejected after this. Validated.",
    "iat":   "Issued-at (unix time).",
    "nbf":   "Not-before (unix time).",
    "nonce": "Replay protection — must match the value your app sent at /login. Validated.",
    "sub":   "Subject — the stable unique user ID at the IdP.",
    "tid":   "Tenant ID (Entra-specific).",
    "email": "User email (from the 'email' scope).",
    "name":  "Display name (from the 'profile' scope).",
}


@app.get("/whoami", response_class=HTMLResponse)
async def whoami(request: Request):
    """LEARNING view: shows the decoded, already-validated ID-token claims.

    This is the *payload* of the ID token (a JWT). Authlib already verified the
    signature (via JWKS) and the iss / aud / exp / nonce before we ever got here —
    so what you see below is trusted, not raw input.
    """
    claims = request.session.get("claims")
    if not claims:
        raise HTTPException(status_code=401, detail="Not authenticated — log in first")

    import html as _html
    rows = []
    for key in sorted(claims, key=lambda k: (k not in _CLAIM_NOTES, k)):
        note = _CLAIM_NOTES.get(key, "")
        rows.append(
            f"<tr><td style='vertical-align:top;font-family:monospace;padding:4px 12px'>{_html.escape(key)}</td>"
            f"<td style='vertical-align:top;font-family:monospace;padding:4px 12px'>{_html.escape(str(claims[key]))}</td>"
            f"<td style='vertical-align:top;padding:4px 12px;color:#555'>{_html.escape(note)}</td></tr>"
        )
    return HTMLResponse(
        "<h3>Your ID token — decoded &amp; validated claims</h3>"
        "<p>This is the JWT <em>payload</em>. The signature, <code>iss</code>, <code>aud</code>, "
        "<code>exp</code> and <code>nonce</code> were already verified before you saw this.</p>"
        "<table style='border-collapse:collapse'>"
        "<tr><th style='text-align:left;padding:4px 12px'>claim</th>"
        "<th style='text-align:left;padding:4px 12px'>value</th>"
        "<th style='text-align:left;padding:4px 12px'>what it means</th></tr>"
        + "".join(rows) +
        "</table><p><a href='/'>home</a> &middot; <a href='/logout'>logout</a></p>"
    )


@app.get("/logout")
async def logout(request: Request):
    # Local logout: clear our session. (Provider-side / RP-initiated logout is a
    # documented enhancement in DESIGN.md.)
    request.session.clear()
    return RedirectResponse(url="/")
