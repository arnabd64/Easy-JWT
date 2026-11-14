import time

import pytest
from hypothesis import HealthCheck
from hypothesis import settings as hyp_settings

from easy_jwt import JWTSettings

from .helpers import AUDIENCE, ISSUER, NOW, SECRET

hyp_settings.register_profile(
    "default",
    max_examples=100,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
hyp_settings.load_profile("default")

ENV_KEYS = (
    "JWT_SECRET",
    "JWT_ACCESS_TTL",
    "JWT_REFRESH_TTL",
    "JWT_ISS",
    "JWT_AUD",
    "JWT_ALGORITHM",
)


class Clock:
    """Controllable replacement for time.time()."""

    def __init__(self, now: int) -> None:
        self.now = now

    def advance(self, seconds: int) -> None:
        self.now += seconds

    def __call__(self) -> float:
        return float(self.now)


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    c = Clock(NOW)
    monkeypatch.setattr(time, "time", c)
    return c


@pytest.fixture
def settings() -> JWTSettings:
    return JWTSettings(
        secret=SECRET,
        access_ttl=300,
        refresh_ttl=3600,
        issuer=ISSUER,
        audience=AUDIENCE,
        algorithm="HS256",
    )


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Valid JWT_* environment; returns the dict of values that were set."""
    values = {
        "JWT_SECRET": SECRET,
        "JWT_ACCESS_TTL": "300",
        "JWT_REFRESH_TTL": "3600",
        "JWT_ISS": ISSUER,
        "JWT_AUD": AUDIENCE,
        "JWT_ALGORITHM": "HS256",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    return values


@pytest.fixture
def no_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
