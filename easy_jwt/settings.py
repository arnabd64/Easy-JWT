"""
Module: easy_jwt.settings
"""

import hashlib
import math
import os
import re
from collections import Counter
from dataclasses import dataclass
from typing import Literal, cast
from urllib.parse import urlsplit

from easy_jwt.exceptions import InvalidSettings

# RFC 3986 scheme and allowed URI characters (unreserved, gen-delims, sub-delims, pct-encoded)
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*$")
_URI_RE = re.compile(r"^(?:[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=]|%[0-9A-Fa-f]{2})+$")

AlgorithmName = Literal["HS256", "HS384", "HS512"]

REQUIRED_ENV_VARIABLES = frozenset(
    [
        "JWT_SECRET",
        "JWT_ACCESS_TTL",
        "JWT_REFRESH_TTL",
        "JWT_ISS",
        "JWT_AUD",
        "JWT_ALGORITHM",
    ]
)

ALGORITHM_MAP = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def shannon_entropy(secret: str) -> float:
    if not secret.strip():
        return 0.0
    length = len(secret)
    frequency = Counter(secret)
    return -sum(
        (count / length) * math.log2(count / length) for count in frequency.values()
    )


@dataclass(frozen=True, slots=True)
class JWTSettings:
    secret: str
    access_ttl: int
    refresh_ttl: int
    issuer: str
    audience: str
    algorithm: AlgorithmName

    def __repr__(self) -> str:
        return (
            "JWTSettings("
            "secret='*****', "
            f"access_ttl={self.access_ttl}, "
            f"refresh_ttl={self.refresh_ttl}, "
            f"issuer={self.issuer!r}, "
            f"audience={self.audience!r}, "
            f"algorithm={self.algorithm!r}"
            ")"
        )

    def __str__(self) -> str:
        return self.__repr__()

    def __post_init__(self) -> None:
        """Validations"""
        # Validate algorithm first (RFC 7518 §3.2 allowlist; needed for key size check)
        if not isinstance(self.algorithm, str) or self.algorithm not in ALGORITHM_MAP:
            raise InvalidSettings(
                f"Invalid algorithm: {self.algorithm!r}. "
                f"Supported algorithms: {', '.join(ALGORITHM_MAP)}."
            )

        # Validate `secret` (RFC 7518 §3.2: key >= hash output size in bytes)
        if not isinstance(self.secret, str):
            raise TypeError("expected str type for secret")

        secret_bytes = self.secret.encode("utf-8")
        min_key_bytes = ALGORITHM_MAP[self.algorithm]().digest_size
        if len(secret_bytes) < min_key_bytes:
            raise InvalidSettings(
                f"Secret key for {self.algorithm} must be at least "
                f"{min_key_bytes} bytes ({min_key_bytes * 8} bits) per RFC 7518"
            )

        total_entropy_bits = shannon_entropy(self.secret) * len(self.secret)
        min_entropy_bits = min_key_bytes * 4
        if total_entropy_bits < min_entropy_bits:
            raise InvalidSettings("secret is cryptographically weak")

        # Validate access_ttl & refresh_ttl (exclude bool since isinstance(True, int) is True)
        if (
            not isinstance(self.access_ttl, int)
            or isinstance(self.access_ttl, bool)
            or not isinstance(self.refresh_ttl, int)
            or isinstance(self.refresh_ttl, bool)
        ):
            raise TypeError("expected int values for access ttl and refresh ttl")
        if self.access_ttl < 30:
            raise InvalidSettings("Access TTL should be at least 30 seconds")
        if self.refresh_ttl < 60:
            raise InvalidSettings("Refresh TTL should be at least 60 seconds")
        if self.refresh_ttl < self.access_ttl:
            raise InvalidSettings("Access TTL is longer than Refresh TTL")

        # Validate iss & aud (RFC 7519 §2, §4.1.1, §4.1.3: StringOrURI)
        self._validate_string_or_uri("issuer", self.issuer)
        self._validate_string_or_uri("audience", self.audience)

    @staticmethod
    def _validate_string_or_uri(field_name: str, value: object) -> None:
        if not isinstance(value, str):
            raise TypeError(f"expected type str for {field_name} field")
        if not value.strip():
            raise InvalidSettings(f"{field_name} field must be a non-empty string")

        # RFC 7519 §2: StringOrURI values containing ":" MUST be valid RFC 3986 URIs
        if ":" not in value:
            return

        if not _URI_RE.fullmatch(value):
            raise InvalidSettings(
                f"{field_name} contains ':' so it must be a valid RFC 3986 URI"
            )

        try:
            parsed = urlsplit(value)
            _ = parsed.port  # Triggers ValueError on out-of-range or malformed ports
        except ValueError as exc:
            raise InvalidSettings(
                f"{field_name} contains ':' so it must be a valid RFC 3986 URI"
            ) from exc

        if not _SCHEME_RE.fullmatch(parsed.scheme) or not (
            parsed.netloc or parsed.path
        ):
            raise InvalidSettings(
                f"{field_name} contains ':' so it must be a valid RFC 3986 URI"
            )

    @classmethod
    def from_env(cls) -> "JWTSettings":
        """Load settings from environment"""
        missing_or_empty = sorted(
            var
            for var in REQUIRED_ENV_VARIABLES
            if var not in os.environ or not os.environ[var].strip()
        )

        if missing_or_empty:
            raise InvalidSettings(
                f"Missing or Empty required Environment Variables: {', '.join(missing_or_empty)}"
            )

        try:
            access_ttl = int(os.environ["JWT_ACCESS_TTL"])
            refresh_ttl = int(os.environ["JWT_REFRESH_TTL"])
        except ValueError as e:
            raise InvalidSettings(
                "TTL environment variables must be valid integers"
            ) from e

        algorithm_raw = os.environ["JWT_ALGORITHM"]
        if algorithm_raw not in ALGORITHM_MAP:
            raise InvalidSettings(
                f"Invalid algorithm: {algorithm_raw!r}. "
                f"Supported algorithms: {', '.join(ALGORITHM_MAP)}."
            )

        return cls(
            secret=os.environ["JWT_SECRET"],
            access_ttl=access_ttl,
            refresh_ttl=refresh_ttl,
            issuer=os.environ["JWT_ISS"],
            audience=os.environ["JWT_AUD"],
            algorithm=cast(AlgorithmName, algorithm_raw),
        )
