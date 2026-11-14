"""
Module: easy_jwt.core

Description:
    - Public APIs for JWT functionalities
"""

import hmac
import time
import uuid
from typing import Literal

from easy_jwt.exceptions import ExpiredToken, InvalidPayload, TokenException
from easy_jwt.payload import Payload
from easy_jwt.settings import ALGORITHM_MAP, JWTSettings
from easy_jwt.utils import (
    RESERVED_CLAIMS,
    generate_token,
    json_decoder,
    url_decoder,
)


def issue_access_token(
    sub: str, custom_claims: dict | None = None, *, settings: JWTSettings | None = None
) -> tuple[str, str]:
    """Issues a new refresh token"""
    # load settings
    settings = settings or JWTSettings.from_env()

    # build payload
    jti: str = str(uuid.uuid4())
    now: int = int(time.time())
    exp: int = now + settings.access_ttl
    payload = Payload(
        jti=jti,
        sub=sub,
        iat=now,
        exp=exp,
        iss=settings.issuer,
        aud=settings.audience,
        token_type="access",
        custom_claims=custom_claims or {},
    )
    return generate_token(payload.flatten_claims(), settings), jti


def issue_refresh_token(
    sub: str, custom_claims: dict | None = None, *, settings: JWTSettings | None = None
) -> tuple[str, str]:
    """Issues a new refresh token"""
    # load settings
    settings = settings or JWTSettings.from_env()

    # build payload
    jti: str = str(uuid.uuid4())
    now: int = int(time.time())
    exp: int = now + settings.refresh_ttl
    payload = Payload(
        jti=jti,
        sub=sub,
        iat=now,
        exp=exp,
        iss=settings.issuer,
        aud=settings.audience,
        token_type="refresh",
        custom_claims=custom_claims or {},
    )
    return generate_token(payload.flatten_claims(), settings), jti


def parse_token(
    token: str,
    *,
    token_type: Literal["access", "refresh"],
    settings: JWTSettings | None = None,
) -> Payload:
    """Validates and decodes a JWT into a Payload instance per RFC 7515 / RFC 7519."""
    if not isinstance(token, str):
        raise TypeError("expected token type to be str")
    if token_type not in {"access", "refresh"}:
        raise ValueError("invalid token_type argument, valid values: access, refresh")

    settings = settings or JWTSettings.from_env()

    # RFC 7515 §3.1 / RFC 7519 §7.2: JWS Compact Serialization must have 3 non-empty parts
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise TokenException("Token is malformed")
    b64_header, b64_payload, b64_signature = parts

    # Verify signature first using configured algorithm (never trust header["alg"] to choose algorithm)
    try:
        actual_sig = url_decoder(b64_signature)
    except ValueError as exc:
        raise TokenException("Malformed token signature") from exc

    # compute expected sign
    expected_sign: bytes = hmac.new(
        key=settings.secret.encode(),
        msg=f"{b64_header}.{b64_payload}".encode(),
        digestmod=ALGORITHM_MAP[settings.algorithm],
    ).digest()

    # compare digests
    if not hmac.compare_digest(actual_sig, expected_sign):
        raise TokenException("Invalid signature")

    # RFC 7515 §4 / RFC 7519 §5, §7.2: Decode and validate JOSE Header
    try:
        header = json_decoder(url_decoder(b64_header))
    except ValueError as exc:
        raise TokenException("Malformed token header") from exc

    if not isinstance(header, dict):
        raise TokenException("Header must be a JSON object")

    alg = header.get("alg")
    if not isinstance(alg, str) or alg != settings.algorithm:
        raise TokenException("Invalid or unsupported 'alg' value in header")

    # RFC 7519 §5.1: 'typ' is optional; if present, media type comparison is case-insensitive
    if "typ" in header:
        typ = header["typ"]
        if not isinstance(typ, str) or typ.upper() not in {"JWT", "APPLICATION/JWT"}:
            raise TokenException("Invalid 'typ' value in header")

    # RFC 7519 §5.2: Nested JWTs / custom content types are not supported
    if "cty" in header:
        raise TokenException("Unsupported 'cty' header parameter")

    # RFC 7515 §4.1.11: Reject tokens with critical extensions since none are supported
    if "crit" in header:
        raise TokenException("Unsupported 'crit' header parameter")

    # RFC 7519 §7.2: Decode and validate JWT Claims Set
    try:
        raw_payload = json_decoder(url_decoder(b64_payload))
    except ValueError as exc:
        raise InvalidPayload("Malformed token payload") from exc

    if not isinstance(raw_payload, dict):
        raise InvalidPayload("Payload must be a JSON object")

    missing_claims = sorted(
        claim
        for claim in RESERVED_CLAIMS
        if claim not in raw_payload and claim != "nbf"
    )
    if missing_claims:
        raise InvalidPayload(f"Missing claims: {', '.join(missing_claims)}")

    if "nbf" in raw_payload and (
        isinstance(raw_payload["nbf"], bool) or not isinstance(raw_payload["nbf"], int)
    ):
        raise InvalidPayload("'nbf' must be an integer NumericDate.")

    # Check expiration before Payload() so ExpiredToken is raised instead of InvalidPayload
    exp = raw_payload["exp"]
    if isinstance(exp, bool) or not isinstance(exp, int):
        raise InvalidPayload("exp is not an integer")
    if time.time() >= exp:
        raise ExpiredToken("Token has expired")

    # Exclude 'nbf' alongside RESERVED_CLAIMS so Payload doesn't reject it inside custom_claims
    known_claims = RESERVED_CLAIMS
    custom_claims = {
        key: value for key, value in raw_payload.items() if key not in known_claims
    }

    payload = Payload(
        jti=raw_payload["jti"],
        sub=raw_payload["sub"],
        iat=raw_payload["iat"],
        exp=exp,
        iss=raw_payload["iss"],
        aud=raw_payload["aud"],
        token_type=raw_payload["token_type"],
        custom_claims=custom_claims,
        nbf=raw_payload.get("nbf"),
    )

    # RFC 7519 §4.1.5: Current time must be >= 'nbf' when 'nbf' is present
    if "nbf" in raw_payload and payload.nbf is not None and time.time() < payload.nbf:
        raise TokenException("Token is not yet valid")

    if payload.token_type != token_type:
        raise TokenException(
            f"expected a {token_type} token, found {payload.token_type} token"
        )

    # RFC 7519 §4.1.1 & §4.1.3: Validate issuer and audience
    if payload.iss != settings.issuer:
        raise InvalidPayload(f"unknown issuer: {payload.iss}")
    if payload.aud != settings.audience:
        raise InvalidPayload(f"unknown audience: {payload.aud}")

    return payload


def verify_token(
    token: str,
    *,
    token_type: Literal["access", "refresh"],
    settings: JWTSettings | None = None,
) -> bool:
    try:
        settings = settings or JWTSettings.from_env()
        _ = parse_token(token, token_type=token_type, settings=settings)
        return True

    except (TypeError, ValueError, TokenException):
        return False


def renew_access_token(
    refresh_token: str, *, settings: JWTSettings | None = None
) -> tuple[str, str]:
    """Issues a new Access Token upon submitting a valid refresh token"""
    settings = settings or JWTSettings.from_env()

    # validate refresh token
    try:
        refresh_payload: Payload = parse_token(
            refresh_token, token_type="refresh", settings=settings
        )

    except (TypeError, ValueError, TokenException):
        raise TokenException("invalid refresh token")

    # build payload
    now: int = int(time.time())
    jti: str = str(uuid.uuid4())
    exp: int = min(refresh_payload.exp, now + settings.access_ttl)

    # new payload
    access_payload = Payload(
        jti=jti,
        sub=refresh_payload.sub,
        iat=now,
        exp=exp,
        iss=settings.issuer,
        aud=settings.audience,
        token_type="access",
        custom_claims=refresh_payload.custom_claims,
    )

    return generate_token(access_payload.flatten_claims(), settings), jti
