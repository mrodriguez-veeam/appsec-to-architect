#!/usr/bin/env python3
"""
decode_jwt.py — decode (NOT verify) a JWT locally, the way an engineer reads one.

A JWT is three base64url segments: header.payload.signature
This prints the header and payload, and renders the time claims (exp/iat/nbf)
as human-readable UTC so you can see expiry/replay details.

  python decode_jwt.py "<paste the id_token from the server log>"

NOTE: this only DECODES. It does NOT verify the signature, issuer, audience, or
expiry — never trust a token just because you can read it. The app (Authlib) is
what actually validates; this tool is for inspection/learning only.
"""
import base64
import datetime as dt
import json
import sys


def _b64url(seg: str) -> bytes:
    seg += "=" * (-len(seg) % 4)          # restore base64 padding
    return base64.urlsafe_b64decode(seg)


def _render_times(claims: dict) -> None:
    for key in ("iat", "nbf", "exp"):
        if isinstance(claims.get(key), (int, float)):
            when = dt.datetime.fromtimestamp(claims[key], dt.timezone.utc)
            print(f"  {key} = {claims[key]}  ->  {when.isoformat()}")


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1].count(".") < 2:
        print("usage: python decode_jwt.py <jwt>   (header.payload.signature)")
        return 2
    header_seg, payload_seg, _sig = sys.argv[1].split(".", 2)
    header = json.loads(_b64url(header_seg))
    payload = json.loads(_b64url(payload_seg))

    print("=== HEADER ===")
    print(json.dumps(header, indent=2))
    print("\n=== PAYLOAD (claims) ===")
    print(json.dumps(payload, indent=2))
    print("\n=== time claims (UTC) ===")
    _render_times(payload)
    print("\n(reminder: decoded only — signature/iss/aud/exp NOT verified here)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
