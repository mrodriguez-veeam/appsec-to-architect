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
            '<p><a href="/me">/me (claims)</a> &middot; <a href="/logout">logout</a></p>'
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

    claims = token.get("userinfo") or {}
    # Store only what the app needs. Do NOT put raw tokens in the cookie.
    request.session["user"] = {
        "sub": claims.get("sub"),
        "email": claims.get("email"),
        "name": claims.get("name"),
    }
    return RedirectResponse(url="/")


@app.get("/me")
async def me(request: Request):
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return JSONResponse(user)


@app.get("/logout")
async def logout(request: Request):
    # Local logout: clear our session. (Provider-side / RP-initiated logout is a
    # documented enhancement in DESIGN.md.)
    request.session.clear()
    return RedirectResponse(url="/")
