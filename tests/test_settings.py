import dataclasses
import hashlib

import pytest

from easy_jwt.exceptions import InvalidSettings
from easy_jwt.settings import (
    ALGORITHM_MAP,
    REQUIRED_ENV_VARIABLES,
    JWTSettings,
    shannon_entropy,
)

from .helpers import (
    AUDIENCE,
    INVALID_URI_WITH_COLON,
    ISSUER,
    SECRET,
    VALID_STRING_OR_URI,
)

HIGH_ENTROPY = {
    "HS256": SECRET[:32],
    "HS384": SECRET[:48],
    "HS512": SECRET[:64],
}


def make(**overrides):
    kwargs = dict(
        secret=SECRET,
        access_ttl=300,
        refresh_ttl=3600,
        issuer=ISSUER,
        audience=AUDIENCE,
        algorithm="HS256",
    )
    kwargs.update(overrides)
    return JWTSettings(**kwargs)


# ---------------------------------------------------------------- entropy
class TestShannonEntropy:
    @pytest.mark.parametrize("secret", ["", " ", "   \t\n"])
    def test_blank_is_zero(self, secret):
        assert shannon_entropy(secret) == 0.0

    def test_single_symbol_is_zero(self):
        assert shannon_entropy("aaaa") == 0.0

    def test_uniform_distribution(self):
        assert shannon_entropy("abcd") == pytest.approx(2.0)
        assert shannon_entropy("ab" * 8) == pytest.approx(1.0)

    def test_skewed_distribution(self):
        assert shannon_entropy("aaab") == pytest.approx(0.8112781244591328)


# ---------------------------------------------------------------- constants
def test_algorithm_map():
    assert ALGORITHM_MAP == {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }


def test_required_env_variables():
    assert REQUIRED_ENV_VARIABLES == {
        "JWT_SECRET",
        "JWT_ACCESS_TTL",
        "JWT_REFRESH_TTL",
        "JWT_ISS",
        "JWT_AUD",
        "JWT_ALGORITHM",
    }


# ---------------------------------------------------------------- dataclass behaviour
class TestDataclass:
    @pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
    def test_valid_construction(self, alg):
        s = make(algorithm=alg)
        assert s.algorithm == alg
        assert s.access_ttl == 300 and s.refresh_ttl == 3600
        assert s.issuer == ISSUER and s.audience == AUDIENCE

    def test_frozen(self):
        s = make()
        with pytest.raises(dataclasses.FrozenInstanceError):
            s.secret = "other"  # type: ignore[misc]

    def test_slots(self):
        assert not hasattr(make(), "__dict__")

    def test_repr_and_str_hide_secret(self):
        s = make()
        for text in (repr(s), str(s), f"{s}", f"{s!r}"):
            assert SECRET not in text
            assert "secret='*****'" in text
            assert "access_ttl=300" in text
            assert "algorithm='HS256'" in text

    def test_equality_and_hash(self):
        assert make() == make()
        assert hash(make()) == hash(make())
        assert make() != make(access_ttl=301)


# ---------------------------------------------------------------- algorithm
class TestAlgorithm:
    @pytest.mark.parametrize(
        "alg",
        ["none", "None", "RS256", "ES256", "hs256", "HS256 ", "", None, 256, b"HS256"],
    )
    def test_rejected(self, alg):
        with pytest.raises(InvalidSettings, match="Invalid algorithm"):
            make(algorithm=alg)


# ---------------------------------------------------------------- secret
class TestSecret:
    @pytest.mark.parametrize("secret", [b"x" * 64, None, 12345, ["a"] * 64])
    def test_non_str(self, secret):
        with pytest.raises(TypeError, match="secret"):
            make(secret=secret)

    @pytest.mark.parametrize(
        ("alg", "size"), [("HS256", 32), ("HS384", 48), ("HS512", 64)]
    )
    def test_minimum_length_enforced(self, alg, size):
        with pytest.raises(InvalidSettings, match=f"at least {size} bytes"):
            make(algorithm=alg, secret=SECRET[: size - 1])
        # exactly the minimum is accepted
        assert make(algorithm=alg, secret=SECRET[:size]).algorithm == alg

    def test_empty_secret(self):
        with pytest.raises(InvalidSettings):
            make(secret="")

    def test_length_is_measured_in_bytes_not_characters(self):
        # 16 two-byte characters == 32 bytes, so the length check passes and entropy rejects it
        secret = "àáâãäåæçèéêëìíîï"
        assert len(secret) == 16 and len(secret.encode()) == 32
        with pytest.raises(InvalidSettings, match="weak"):
            make(secret=secret)

    @pytest.mark.parametrize("secret", ["a" * 64, " " * 64, "ab" * 32, "abc" * 22])
    def test_low_entropy_rejected(self, secret):
        with pytest.raises(InvalidSettings, match="cryptographically weak"):
            make(secret=secret)

    def test_entropy_boundary_is_inclusive(self):
        # 16 distinct chars, each twice: exactly 4 bits/char * 32 chars = 128 bits (the HS256 minimum)
        secret = "".join(c * 2 for c in "ABCDEFGHIJKLMNOP")
        assert make(secret=secret).secret == secret
        # 8 distinct chars, each four times: 96 bits
        with pytest.raises(InvalidSettings, match="weak"):
            make(secret="".join(c * 4 for c in "ABCDEFGH"))

    def test_error_message_never_contains_the_secret(self):
        weak = "x" * 40 + "yz"
        for kwargs in ({"secret": weak}, {"secret": weak[:10]}):
            with pytest.raises(InvalidSettings) as info:
                make(**kwargs)
            assert kwargs["secret"] not in str(info.value)


# ---------------------------------------------------------------- ttl
class TestTTL:
    @pytest.mark.parametrize("value", [True, False, 300.0, "300", None, b"300"])
    def test_access_ttl_type(self, value):
        with pytest.raises(TypeError, match="ttl"):
            make(access_ttl=value)

    @pytest.mark.parametrize("value", [True, False, 3600.0, "3600", None])
    def test_refresh_ttl_type(self, value):
        with pytest.raises(TypeError, match="ttl"):
            make(refresh_ttl=value)

    @pytest.mark.parametrize("value", [29, 0, -1, -(10**9)])
    def test_access_ttl_minimum(self, value):
        with pytest.raises(InvalidSettings, match="Access TTL should be at least 30"):
            make(access_ttl=value)

    def test_access_ttl_boundary(self):
        assert make(access_ttl=30).access_ttl == 30

    @pytest.mark.parametrize("value", [59, 0, -1])
    def test_refresh_ttl_minimum(self, value):
        with pytest.raises(InvalidSettings, match="Refresh TTL should be at least 60"):
            make(refresh_ttl=value)

    def test_refresh_ttl_boundary(self):
        assert make(access_ttl=30, refresh_ttl=60).refresh_ttl == 60

    def test_refresh_must_not_be_shorter_than_access(self):
        with pytest.raises(InvalidSettings, match="longer than Refresh"):
            make(access_ttl=500, refresh_ttl=499)

    def test_equal_ttls_allowed(self):
        assert make(access_ttl=100, refresh_ttl=100).refresh_ttl == 100


# ---------------------------------------------------------------- issuer / audience


@pytest.mark.parametrize("field", ["issuer", "audience"])
class TestIssuerAudience:
    @pytest.mark.parametrize("value", VALID_STRING_OR_URI)
    def test_valid(self, field, value):
        assert getattr(make(**{field: value}), field) == value

    @pytest.mark.parametrize("value", [None, 1, b"x", ["a"], True])
    def test_non_str(self, field, value):
        with pytest.raises(TypeError, match=field):
            make(**{field: value})

    @pytest.mark.parametrize("value", ["", " ", "\t\n"])
    def test_blank(self, field, value):
        with pytest.raises(InvalidSettings, match="non-empty"):
            make(**{field: value})

    @pytest.mark.parametrize("value", INVALID_URI_WITH_COLON)
    def test_invalid_uri(self, field, value):
        with pytest.raises(InvalidSettings, match="RFC 3986"):
            make(**{field: value})


# ---------------------------------------------------------------- from_env
class TestFromEnv:
    def test_success(self, env):
        s = JWTSettings.from_env()
        assert s == make()

    @pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
    def test_each_algorithm(self, env, monkeypatch, alg):
        monkeypatch.setenv("JWT_ALGORITHM", alg)
        assert JWTSettings.from_env().algorithm == alg

    def test_all_missing_are_listed_sorted(self, monkeypatch):
        for key in REQUIRED_ENV_VARIABLES:
            monkeypatch.delenv(key, raising=False)
        with pytest.raises(InvalidSettings) as info:
            JWTSettings.from_env()
        message = str(info.value)
        names = message.split(": ", 1)[1].split(", ")
        assert names == sorted(REQUIRED_ENV_VARIABLES)

    @pytest.mark.parametrize("key", sorted(REQUIRED_ENV_VARIABLES))
    def test_single_missing(self, env, monkeypatch, key):
        monkeypatch.delenv(key)
        with pytest.raises(InvalidSettings, match=key):
            JWTSettings.from_env()

    @pytest.mark.parametrize("key", sorted(REQUIRED_ENV_VARIABLES))
    @pytest.mark.parametrize("blank", ["", "   ", "\t"])
    def test_blank_values(self, env, monkeypatch, key, blank):
        monkeypatch.setenv(key, blank)
        with pytest.raises(InvalidSettings, match=key):
            JWTSettings.from_env()

    @pytest.mark.parametrize("key", ["JWT_ACCESS_TTL", "JWT_REFRESH_TTL"])
    @pytest.mark.parametrize("value", ["abc", "30.5", "1e3", "0x20"])
    def test_ttl_must_be_integer(self, env, monkeypatch, key, value):
        monkeypatch.setenv(key, value)
        with pytest.raises(InvalidSettings, match="valid integers"):
            JWTSettings.from_env()

    @pytest.mark.parametrize("alg", ["none", "RS256", "hs256", "HS256 "])
    def test_invalid_algorithm(self, env, monkeypatch, alg):
        monkeypatch.setenv("JWT_ALGORITHM", alg)
        with pytest.raises(InvalidSettings, match="Invalid algorithm"):
            JWTSettings.from_env()

    def test_values_are_validated_after_loading(self, env, monkeypatch):
        monkeypatch.setenv("JWT_SECRET", "short-and-weak")
        with pytest.raises(InvalidSettings, match="at least 32 bytes"):
            JWTSettings.from_env()
