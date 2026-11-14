"""RFC 7519 (JSON Web Token) conformance."""

import json

import pytest

from easy_jwt import issue_access_token, issue_refresh_token, parse_token
from easy_jwt.exceptions import ExpiredToken, InvalidPayload, TokenException

from .helpers import (
    AUDIENCE,
    ISSUER,
    NOW,
    decode_part,
    forge,
    make_settings,
    split,
    valid_claims,
    without,
)

pytestmark = pytest.mark.usefixtures("clock")


def parse(token, settings, kind="access"):
    return parse_token(token, token_type=kind, settings=settings)


class TestSection2Terminology:
    @pytest.mark.parametrize("claim", ["iat", "exp", "nbf"])
    @pytest.mark.parametrize("bad", ["1700000300", True, None, [1700000300], {"v": 1}])
    def test_numericdate_must_be_a_json_number(self, claim, bad, settings):
        with pytest.raises(InvalidPayload):
            parse(forge(payload=valid_claims(**{claim: bad})), settings)

    def test_numericdate_negative_is_rejected(self, settings):
        # library policy: seconds since the epoch must be non-negative
        with pytest.raises(InvalidPayload):
            parse(forge(payload=valid_claims(nbf=-1)), settings)

    def test_numericdate_non_integer_is_rejected_by_policy(self, settings):
        # RFC 7519 §2 permits fractional NumericDate values; this library deliberately only accepts
        # integers. Pinned here so a change of policy is a conscious decision.
        with pytest.raises(InvalidPayload):
            parse(forge(payload=valid_claims(nbf=NOW + 0.5)), settings)

    @pytest.mark.parametrize("claim", ["iss", "sub", "aud"])
    @pytest.mark.parametrize(
        "value", ["no-colon", "https://example.com/path", "urn:isbn:0451450523"]
    )
    def test_stringorURI_accepts_arbitrary_strings_and_uris(self, claim, value):
        overrides = {"iss": "issuer", "aud": "audience"}
        s = (
            make_settings(**{overrides[claim]: value})
            if claim in overrides
            else make_settings()
        )
        assert (
            getattr(parse(forge(payload=valid_claims(**{claim: value})), s), claim)
            == value
        )

    @pytest.mark.parametrize("claim", ["iss", "sub", "aud"])
    @pytest.mark.parametrize(
        "value", ["not a uri: x", "http://host:99999", "http:", "1x://y"]
    )
    def test_stringorURI_with_colon_must_be_a_valid_uri(self, claim, value, settings):
        # §2: "Any string containing a ':' character MUST be a URI"
        with pytest.raises(InvalidPayload):
            parse(forge(payload=valid_claims(**{claim: value})), settings)

    def test_claim_names_are_case_sensitive(self, settings):
        # §4: "Claim Names are case sensitive": "EXP" is not "exp"
        token = forge(payload=valid_claims(EXP=1, Sub="x"))
        assert parse(token, settings).custom_claims == {"EXP": 1, "Sub": "x"}

    def test_uppercase_registered_name_does_not_satisfy_the_requirement(self, settings):
        claims = valid_claims()
        claims["EXP"] = claims.pop("exp")
        with pytest.raises(InvalidPayload, match="Missing claims: exp"):
            parse(forge(payload=claims), settings)


class TestSection4RegisteredClaims:
    def test_4_1_1_issuer_is_checked(self, settings):
        with pytest.raises(InvalidPayload, match="issuer"):
            parse(forge(payload=valid_claims(iss="someone-else")), settings)

    def test_4_1_3_audience_is_checked(self, settings):
        with pytest.raises(InvalidPayload, match="audience"):
            parse(forge(payload=valid_claims(aud="another-service")), settings)

    def test_4_1_4_expired_token_is_rejected(self, clock, settings):
        # "the current date/time MUST be before the expiration date/time"
        token = forge()
        clock.now = NOW + 300 - 1
        assert parse(token, settings)
        clock.now = NOW + 300
        with pytest.raises(ExpiredToken):
            parse(token, settings)

    def test_4_1_5_nbf_in_future_is_rejected(self, clock, settings):
        # "the current date/time MUST be after or equal to the not-before date/time"
        token = forge(payload=valid_claims(nbf=NOW + 100))
        with pytest.raises(TokenException, match="not yet valid"):
            parse(token, settings)
        clock.now = NOW + 100
        assert parse(token, settings)

    def test_4_1_5_nbf_is_optional(self, settings):
        assert parse(forge(payload=without(valid_claims(), "nbf")), settings)

    def test_4_1_6_iat_is_carried_through(self, settings):
        assert (
            parse(forge(payload=valid_claims(iat=NOW - 50, nbf=NOW - 50)), settings).iat
            == NOW - 50
        )

    def test_4_1_7_jti_is_a_case_sensitive_string(self, settings):
        a = parse(forge(payload=valid_claims(jti="AbC")), settings).jti
        b = parse(forge(payload=valid_claims(jti="abc")), settings).jti
        assert (a, b) == ("AbC", "abc")

    @pytest.mark.parametrize("kind", ["access", "refresh"])
    def test_issued_tokens_contain_the_claims_set_this_profile_requires(
        self, kind, settings
    ):
        issue = issue_access_token if kind == "access" else issue_refresh_token
        token, _ = issue("alice", settings=settings)
        claims = json.loads(decode_part(split(token)[1]))
        assert {"jti", "sub", "iss", "aud", "iat", "nbf", "exp", "token_type"} <= set(
            claims
        )
        assert claims["iss"] == ISSUER and claims["aud"] == AUDIENCE


class TestSection5Header:
    @pytest.mark.parametrize(
        "typ", ["JWT", "jwt", "application/jwt", "Application/JWT"]
    )
    def test_5_1_typ_is_a_case_insensitive_media_type(self, typ, settings):
        assert parse(forge({"alg": "HS256", "typ": typ}), settings)

    def test_5_1_typ_is_optional(self, settings):
        assert parse(forge({"alg": "HS256"}), settings)

    def test_5_2_cty_signals_a_nested_jwt_which_is_unsupported(self, settings):
        with pytest.raises(TokenException, match="cty"):
            parse(forge({"alg": "HS256", "typ": "JWT", "cty": "JWT"}), settings)

    def test_5_3_unsecured_jwt_alg_none_is_rejected(self, settings):
        with pytest.raises(TokenException):
            parse(forge({"alg": "none", "typ": "JWT"}), settings)


class TestSection7_2Validation:
    def test_jws_must_have_three_non_empty_parts(self, settings):
        for token in ("", "a.b", "a.b.c.d", "a..c"):
            with pytest.raises(TokenException):
                parse(token, settings)

    def test_signature_checked_before_claims_are_trusted(self, settings):
        token = forge(secret="Z" * 64, payload=valid_claims(sub="admin"))
        with pytest.raises(TokenException, match="Invalid signature"):
            parse(token, settings)

    def test_claims_set_must_be_a_json_object(self, settings):
        with pytest.raises(InvalidPayload, match="JSON object"):
            parse(forge(payload=b"[]"), settings)

    def test_claims_set_member_names_must_be_unique(self, settings):
        # §4: "The Claim Names within a JWT Claims Set MUST be unique"
        with pytest.raises(InvalidPayload):
            parse(forge(payload=b'{"sub":"a","sub":"b"}'), settings)


class TestIssuedTokensAreValidJsonPerRfc8259:
    @pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
    def test_issuing_must_not_emit_non_finite_numbers(self, bad, settings):
        # NaN/Infinity are not JSON (RFC 8259 §6). A token containing them cannot be parsed by any
        # compliant implementation, so issuing must fail instead of emitting it.
        with pytest.raises((ValueError, InvalidPayload)):
            issue_refresh_token("alice", {"score": bad}, settings=settings)
