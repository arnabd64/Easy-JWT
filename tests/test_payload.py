import time
from types import MappingProxyType

import pytest

from easy_jwt.exceptions import InvalidPayload
from easy_jwt.payload import Payload

from .helpers import (
    AUDIENCE,
    INVALID_URI_WITH_COLON,
    ISSUER,
    NOW,
    VALID_STRING_OR_URI,
)

RESERVED = ["jti", "sub", "iat", "exp", "iss", "aud", "nbf", "token_type"]


@pytest.fixture(autouse=True)
def _frozen_clock(clock):
    return clock


def make(**overrides):
    kwargs = dict(
        jti="jti-1",
        sub="user-1",
        iat=NOW,
        exp=NOW + 300,
        iss=ISSUER,
        aud=AUDIENCE,
        token_type="access",
    )
    kwargs.update(overrides)
    return Payload(**kwargs)


class TestConstruction:
    def test_defaults(self):
        p = make()
        assert p.nbf == p.iat  # nbf defaults to iat
        assert p.custom_claims == {}

    def test_explicit_nbf_kept(self):
        assert make(nbf=NOW + 10).nbf == NOW + 10

    def test_custom_claims_none_becomes_empty_dict(self):
        assert make(custom_claims=None).custom_claims == {}

    def test_custom_claims_are_copied(self):
        source = {"role": "admin", "nested": {"a": 1}}
        p = make(custom_claims=source)
        source["role"] = "root"
        assert p.custom_claims["role"] == "admin"
        assert isinstance(p.custom_claims, dict)

    def test_any_mapping_is_accepted_and_converted(self):
        p = make(custom_claims=MappingProxyType({"a": 1}))
        assert p.custom_claims == {"a": 1} and type(p.custom_claims) is dict

    @pytest.mark.parametrize("value", [[("a", 1)], "abc", 5, ("a",), {"a"}, object()])
    def test_custom_claims_must_be_mapping(self, value):
        with pytest.raises(InvalidPayload, match="must be a mapping"):
            make(custom_claims=value)

    @pytest.mark.parametrize("key", ["", " ", "\t\n", 1, None, b"k", ("a",)])
    def test_custom_claim_keys_must_be_non_empty_strings(self, key):
        with pytest.raises(InvalidPayload, match="custom_claims key"):
            make(custom_claims={key: 1})

    @pytest.mark.parametrize("name", RESERVED)
    def test_cannot_override_reserved_claim(self, name):
        with pytest.raises(
            InvalidPayload, match=f"cannot override reserved claims: {name}"
        ):
            make(custom_claims={name: "x"})

    def test_conflicts_are_listed_sorted(self):
        with pytest.raises(InvalidPayload, match="exp, sub"):
            make(custom_claims={"sub": "a", "exp": 1, "ok": 2})

    def test_reserved_names_are_case_sensitive(self):
        # "Sub" is a different claim name per RFC 7519 §4 ("case sensitive")
        assert make(custom_claims={"Sub": "x", "EXP": 1}).custom_claims == {
            "Sub": "x",
            "EXP": 1,
        }

    def test_returns_flat_equal_dataclasses(self):
        assert make() == make()
        assert make() != make(sub="other")


class TestStringFields:
    @pytest.mark.parametrize("value", ["", " ", "\t\n", None, 1, b"x", ["a"], True])
    def test_jti_must_be_non_empty_string(self, value):
        with pytest.raises(InvalidPayload, match="'jti'"):
            make(jti=value)

    @pytest.mark.parametrize("field", ["iss", "sub", "aud"])
    class TestStringOrUri:
        @pytest.mark.parametrize("value", VALID_STRING_OR_URI)
        def test_valid(self, field, value):
            assert getattr(make(**{field: value}), field) == value

        @pytest.mark.parametrize(
            "value", ["", " ", None, 1, b"x", ["a"], {"a": 1}, True]
        )
        def test_non_string_or_blank(self, field, value):
            with pytest.raises(
                InvalidPayload, match=f"'{field}' must be a non-empty string"
            ):
                make(**{field: value})

        @pytest.mark.parametrize("value", INVALID_URI_WITH_COLON)
        def test_invalid_uri(self, field, value):
            with pytest.raises(InvalidPayload, match="RFC 3986"):
                make(**{field: value})


class TestNumericDates:
    @pytest.mark.parametrize("field", ["iat", "exp", "nbf"])
    @pytest.mark.parametrize(
        "value", [1.5, 1e10, "1700000000", "x", True, False, [1], {"a": 1}]
    )
    def test_must_be_integers(self, field, value):
        with pytest.raises(
            InvalidPayload, match=f"'{field}' must be an integer NumericDate"
        ):
            make(**{field: value})

    @pytest.mark.parametrize("field", ["iat", "exp", "nbf"])
    def test_must_be_non_negative(self, field):
        with pytest.raises(InvalidPayload, match=f"'{field}' must be a non-negative"):
            make(**{field: -1})

    def test_zero_is_a_valid_numeric_date(self):
        # iat/nbf of 0 (epoch) are valid NumericDates
        assert make(iat=0, nbf=0).iat == 0


class TestTemporalConsistency:
    def test_exp_must_exceed_iat(self):
        with pytest.raises(
            InvalidPayload, match="'exp' must be strictly greater than 'iat'"
        ):
            make(iat=NOW + 100, exp=NOW + 100, nbf=NOW)
        with pytest.raises(InvalidPayload, match="strictly greater than 'iat'"):
            make(iat=NOW + 100, exp=NOW + 99, nbf=NOW)

    def test_exp_must_exceed_nbf(self):
        with pytest.raises(
            InvalidPayload, match="'exp' must be strictly greater than 'nbf'"
        ):
            make(nbf=NOW + 300)
        with pytest.raises(InvalidPayload, match="strictly greater than 'nbf'"):
            make(nbf=NOW + 301)

    def test_nbf_before_exp_is_fine_even_if_in_future(self):
        assert make(nbf=NOW + 299).nbf == NOW + 299

    def test_already_expired(self, clock):
        with pytest.raises(InvalidPayload, match="expired"):
            make(iat=NOW - 1000, exp=NOW - 10, nbf=NOW - 1000)

    def test_expiry_boundary_now_equals_exp_is_expired(self, clock):
        with pytest.raises(InvalidPayload, match="expired"):
            make(iat=NOW - 10, exp=NOW, nbf=NOW - 10)
        assert make(iat=NOW - 10, exp=NOW + 1, nbf=NOW - 10).exp == NOW + 1

    def test_uses_current_time_not_import_time(self, clock):
        p = make()
        clock.advance(10_000)
        with pytest.raises(InvalidPayload, match="expired"):
            make()  # same arguments are now stale
        assert p.exp == NOW + 300


class TestTokenType:
    @pytest.mark.parametrize("value", ["access", "refresh"])
    def test_valid(self, value):
        assert make(token_type=value).token_type == value

    @pytest.mark.parametrize(
        "value", ["ACCESS", "bearer", "", "id", None, 1, ["access"], b"access"]
    )
    def test_invalid(self, value):
        with pytest.raises(InvalidPayload, match="'token_type' must be either"):
            make(token_type=value)


class TestFlattenClaims:
    def test_contains_every_claim(self):
        p = make(custom_claims={"role": "admin"}, nbf=NOW + 5)
        assert p.flatten_claims() == {
            "role": "admin",
            "jti": "jti-1",
            "sub": "user-1",
            "iss": ISSUER,
            "aud": AUDIENCE,
            "iat": NOW,
            "nbf": NOW + 5,
            "exp": NOW + 300,
            "token_type": "access",
        }

    def test_without_custom_claims(self):
        assert set(make().flatten_claims()) == set(RESERVED)

    def test_registered_claims_win_over_custom_claims(self):
        p = make(custom_claims={"role": "x"})
        p.custom_claims["sub"] = "attacker"  # bypass validation post-construction
        assert p.flatten_claims()["sub"] == "user-1"

    def test_flatten_does_not_mutate(self):
        p = make(custom_claims={"a": 1})
        p.flatten_claims()["a"] = 2
        assert p.custom_claims == {"a": 1}

    def test_flatten_with_cleared_custom_claims(self):
        p = make()
        p.custom_claims = None  # dataclass is mutable; flatten must tolerate it
        assert p.flatten_claims()["sub"] == "user-1"
