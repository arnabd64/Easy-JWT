"""
Module: easy_jwt.payload
"""

import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlsplit

from easy_jwt.exceptions import InvalidPayload

# RFC 3986 scheme and allowed URI characters (unreserved, gen-delims, sub-delims, pct-encoded)
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*$")
_URI_RE = re.compile(r"^(?:[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=]|%[0-9A-Fa-f]{2})+$")

_RESERVED_CLAIMS = frozenset(
    {"jti", "sub", "iat", "exp", "iss", "aud", "nbf", "token_type"}
)


@dataclass
class Payload:
    jti: str
    sub: str
    iat: int
    exp: int
    iss: str
    aud: str
    token_type: Literal["access", "refresh"]
    custom_claims: Mapping[str, Any] | None = None
    nbf: int | None = None

    def __post_init__(self) -> None:
        if self.nbf is None:
            self.nbf = self.iat

        if self.custom_claims is None:
            self.custom_claims = {}
        elif not isinstance(self.custom_claims, Mapping):
            raise InvalidPayload("'custom_claims' must be a mapping.")
        else:
            for key in self.custom_claims:
                self._validate_non_empty_str("custom_claims key", key)

            conflicting_claims = set(self.custom_claims.keys()) & _RESERVED_CLAIMS
            if conflicting_claims:
                raise InvalidPayload(
                    "Custom claims cannot override reserved claims: "
                    f"{', '.join(sorted(conflicting_claims))}."
                )

            self.custom_claims = dict(self.custom_claims)

        # RFC 7519 §4.1.7: "jti" is a case-sensitive string
        self._validate_non_empty_str("jti", self.jti)

        # RFC 7519 §4.1.1–4.1.3: "iss", "sub", and "aud" are StringOrURI values
        for field_name in ("iss", "sub", "aud"):
            self._validate_string_or_uri(field_name, getattr(self, field_name))

        # RFC 7519 §4.1.4–4.1.6: "exp", "nbf", and "iat" are NumericDate values
        for field_name in ("iat", "exp", "nbf"):
            self._validate_numeric_date(field_name, getattr(self, field_name))

        # Temporal consistency checks
        if self.exp <= self.iat:
            raise InvalidPayload("'exp' must be strictly greater than 'iat'.")

        if self.exp <= self.nbf:
            raise InvalidPayload("'exp' must be strictly greater than 'nbf'.")

        # RFC 7519 §4.1.4: current date/time MUST be before "exp"
        if self.exp <= time.time():
            raise InvalidPayload("Token is expired ('exp' must be in the future).")

        # Application-specific private claim validation
        if not isinstance(self.token_type, str) or self.token_type not in (
            "access",
            "refresh",
        ):
            raise InvalidPayload("'token_type' must be either 'access' or 'refresh'.")

    def flatten_claims(self) -> Mapping[str, Any]:
        return {
            **(self.custom_claims or {}),
            "jti": self.jti,
            "sub": self.sub,
            "iss": self.iss,
            "aud": self.aud,
            "iat": self.iat,
            "nbf": self.nbf,
            "exp": self.exp,
            "token_type": self.token_type,
        }

    @staticmethod
    def _validate_non_empty_str(field_name: str, value: object) -> None:
        if not isinstance(value, str) or not value.strip():
            raise InvalidPayload(f"'{field_name}' must be a non-empty string.")

    @classmethod
    def _validate_string_or_uri(cls, field_name: str, value: object) -> None:
        cls._validate_non_empty_str(field_name, value)
        assert isinstance(value, str)

        # RFC 7519 §2: StringOrURI may be an arbitrary string,
        # but any value containing ":" MUST be a valid RFC 3986 URI.
        if ":" not in value:
            return

        if not _URI_RE.fullmatch(value):
            raise InvalidPayload(
                f"'{field_name}' contains ':' so it must be a valid RFC 3986 URI."
            )

        try:
            parsed = urlsplit(value)
            _ = parsed.port  # Triggers ValueError on malformed ports
        except ValueError as exc:
            raise InvalidPayload(
                f"'{field_name}' contains ':' so it must be a valid RFC 3986 URI."
            ) from exc

        if not _SCHEME_RE.fullmatch(parsed.scheme) or not (
            parsed.netloc or parsed.path
        ):
            raise InvalidPayload(
                f"'{field_name}' contains ':' so it must be a valid RFC 3986 URI."
            )

    @staticmethod
    def _validate_numeric_date(field_name: str, value: object) -> None:
        # Exclude bool because isinstance(True, int) is True in Python
        if not isinstance(value, int) or isinstance(value, bool):
            raise InvalidPayload(f"'{field_name}' must be an integer NumericDate.")
        if value < 0:
            raise InvalidPayload(
                f"'{field_name}' must be a non-negative NumericDate (seconds since Unix epoch)."
            )
