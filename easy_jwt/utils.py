"""
Module: easy_jwt.utils
"""

import base64
import binascii
import hmac
import json
import math
import re
from collections.abc import Mapping
from typing import Any

from easy_jwt.settings import ALGORITHM_MAP, JWTSettings

RESERVED_CLAIMS = frozenset(
    ["jti", "sub", "iat", "nbf", "exp", "iss", "aud", "token_type"]
)
_B64URL_RE = re.compile(r"[A-Za-z0-9_-]*")
_B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_B64URL_INDEX = {ch: idx for idx, ch in enumerate(_B64URL_ALPHABET)}
_MAX_INT_DIGITS = 4300


def _reject_non_finite_constant(val: str) -> None:
    raise ValueError(f"Non-finite JSON constant is not allowed: {val}")


def _parse_finite_float(val: str) -> float:
    num = float(val)
    if not math.isfinite(num):
        raise ValueError(f"Non-finite JSON float is not allowed: {val}")
    return num


def _parse_int(val: str) -> int:
    digit_count = len(val) - (1 if val.startswith("-") else 0)
    if digit_count > _MAX_INT_DIGITS:
        raise ValueError("JSON integer exceeds maximum allowed digits")
    return int(val)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"Duplicate JSON key is not allowed: {key!r}")
        obj[key] = value
    return obj


def _validate_unicode_scalars(value: Any) -> None:
    """Reject lone UTF-16 surrogates (e.g. \\uD800) per RFC 8259 §8.2."""
    if isinstance(value, str):
        # Raises UnicodeEncodeError (a ValueError subclass) on lone surrogates
        value.encode("utf-8")
    elif isinstance(value, dict):
        for k, v in value.items():
            k.encode("utf-8")
            _validate_unicode_scalars(v)
    elif isinstance(value, list):
        for item in value:
            _validate_unicode_scalars(item)


def json_encoder(data: Mapping[str, Any]) -> bytes:
    # allow_nan=False raises ValueError on NaN, Infinity, -Infinity per RFC 8259 §6
    return json.dumps(data, allow_nan=False, separators=(",", ":")).encode()


def json_decoder(data: bytes | bytearray | str) -> Any:
    """Decode strict UTF-8 JSON per RFC 8259, RFC 7515 §4, and RFC 7519 §4."""
    if isinstance(data, (bytes, bytearray)):
        # RFC 8259 §8.1: Strict UTF-8 (leading U+FEFF BOM is rejected by json.loads)
        text = bytes(data).decode("utf-8")
    elif isinstance(data, str):
        data.encode("utf-8")  # Reject raw lone surrogates
        text = data
    else:
        raise TypeError("expected bytes, bytearray, or str for JSON input")

    try:
        parsed = json.loads(
            text,
            parse_constant=_reject_non_finite_constant,
            parse_float=_parse_finite_float,
            parse_int=_parse_int,
            object_pairs_hook=_reject_duplicate_keys,
        )
        _validate_unicode_scalars(parsed)
        return parsed
    except RecursionError as exc:
        raise ValueError("JSON nesting depth exceeded") from exc


def url_decoder(b64_data: str) -> bytes:
    """Decode canonical unpadded base64url per RFC 4648 §3.5, §5 and RFC 7515 §2."""
    if not isinstance(b64_data, str):
        raise TypeError("expected str for base64url input")
    if not _B64URL_RE.fullmatch(b64_data):
        raise ValueError("Invalid base64url characters")

    rem = len(b64_data) % 4
    if rem == 1:
        raise ValueError("Invalid base64url length")

    # RFC 4648 §3.5: Unused trailing pad bits MUST be zero (canonical encoding)
    if rem in (2, 3) and b64_data != "-_":
        last_val = _B64URL_INDEX[b64_data[-1]]
        mask = 0x0F if rem == 2 else 0x03
        if last_val & mask:
            raise ValueError("Non-canonical base64url encoding: non-zero padding bits")

    pad = "=" * ((4 - rem) % 4)
    try:
        return base64.urlsafe_b64decode(b64_data + pad)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Invalid base64url encoding") from exc


def generate_token(payload: Mapping[str, Any], settings: JWTSettings) -> str:
    # build header
    header = {"typ": "JWT", "alg": settings.algorithm}

    # encode header
    b64_header: str = (
        base64.urlsafe_b64encode(json_encoder(header)).rstrip(b"=").decode()
    )

    # encode payload
    b64_payload: str = (
        base64.urlsafe_b64encode(json_encoder(payload)).rstrip(b"=").decode()
    )

    # sign header & payload
    raw_signature = hmac.new(
        key=settings.secret.encode(),
        msg=f"{b64_header}.{b64_payload}".encode(),
        digestmod=ALGORITHM_MAP[settings.algorithm],
    ).digest()

    # convert to base64
    b64_signature: str = base64.urlsafe_b64encode(raw_signature).rstrip(b"=").decode()

    return f"{b64_header}.{b64_payload}.{b64_signature}"
