"""Shared helpers for forging and inspecting tokens independently of easy_jwt."""

import base64
import hashlib
import hmac
import json
from typing import Any

from easy_jwt.settings import JWTSettings

SECRET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"  # 64 distinct chars
ISSUER = "test-issuer"
AUDIENCE = "test-audience"
NOW = 1_700_000_000

HASHES = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jdump(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode()


def hs_sign(signing_input: str, secret: str = SECRET, alg: str = "HS256") -> str:
    digest = hmac.new(secret.encode(), signing_input.encode(), HASHES[alg]).digest()
    return b64(digest)


def forge(
    header: dict | bytes | None = None,
    payload: dict | bytes | None = None,
    *,
    secret: str = SECRET,
    sign_alg: str = "HS256",
    signature: str | None = None,
) -> str:
    """Build a compact JWS. dict -> JSON, bytes -> used verbatim (for malformed input).

    The signature is a *correct* HMAC over the exact bytes unless `signature` is given,
    so tests reach the checks that run after signature verification.
    """
    if header is None:
        header = {"typ": "JWT", "alg": "HS256"}
    if payload is None:
        payload = valid_claims()
    h = b64(header if isinstance(header, bytes) else jdump(header))
    p = b64(payload if isinstance(payload, bytes) else jdump(payload))
    sig = signature if signature is not None else hs_sign(f"{h}.{p}", secret, sign_alg)
    return f"{h}.{p}.{sig}"


def valid_claims(now: int = NOW, **overrides: Any) -> dict:
    claims = {
        "jti": "11111111-1111-4111-8111-111111111111",
        "sub": "user-1",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "token_type": "access",
    }
    claims.update(overrides)
    return claims


def without(claims: dict, *names: str) -> dict:
    return {k: v for k, v in claims.items() if k not in names}


def decode_part(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def split(token: str) -> tuple[str, str, str]:
    h, p, s = token.split(".")
    return h, p, s


# StringOrURI samples shared by settings and payload tests (RFC 7519 §2, RFC 3986)
VALID_STRING_OR_URI = [
    "plain",
    "with spaces and unicode é",  # no ':' so any string is fine
    "https://example.com",
    "https://example.com:8443/path?q=1#frag",
    "urn:example:service",
    "mailto:someone@example.com",
    "a:b",
    "http://[::1]:8080/",
    "https://example.com/%E2%9C%93",
]
INVALID_URI_WITH_COLON = [
    "has space:x",  # character outside the RFC 3986 set
    "https://exa mple.com",
    "https://example.com/ü",  # non-ASCII
    "https://example.com/%zz",  # bad percent-encoding
    "http://host:99999",  # port out of range
    "http://host:abc",  # port not numeric
    "http:",  # scheme but neither authority nor path
    "a:",
    "1http://x",  # scheme must start with a letter
    ":",
    "://x",
    "x\n:y",
]


def make_settings(alg: str = "HS256", **kw: Any) -> JWTSettings:
    kwargs: dict[str, Any] = dict(
        secret=SECRET,
        access_ttl=300,
        refresh_ttl=3600,
        issuer=ISSUER,
        audience=AUDIENCE,
        algorithm=alg,
    )
    kwargs.update(kw)
    return JWTSettings(**kwargs)
