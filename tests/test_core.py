import json
import uuid

import pytest

from easy_jwt import (
    JWTSettings,
    issue_access_token,
    issue_refresh_token,
    parse_token,
    renew_access_token,
    verify_token,
)
from easy_jwt.exceptions import (
    ExpiredToken,
    InvalidPayload,
    InvalidSettings,
    TokenException,
)
from easy_jwt.payload import Payload

from .helpers import (
    AUDIENCE,
    ISSUER,
    NOW,
    SECRET,
    b64,
    decode_part,
    forge,
    hs_sign,
    jdump,
    make_settings,
    split,
    valid_claims,
    without,
)

TYPES = ("access", "refresh")
ISSUERS = {"access": issue_access_token, "refresh": issue_refresh_token}


def claims_of(token):
    return json.loads(decode_part(split(token)[1]))


def assert_rejected(token, exc, match, settings, token_type="access"):
    """The *exact* exception class matters: ExpiredToken/InvalidPayload are subclasses."""
    with pytest.raises(exc, match=match) as info:
        parse_token(token, token_type=token_type, settings=settings)
    assert type(info.value) is exc


# ============================================================ issuing
@pytest.mark.usefixtures("clock")
class TestIssue:
    @pytest.mark.parametrize("kind", TYPES)
    @pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
    def test_roundtrip(self, kind, alg):
        s = make_settings(alg)
        token, jti = ISSUERS[kind]("alice", settings=s)
        payload = parse_token(token, token_type=kind, settings=s)
        assert isinstance(payload, Payload)
        assert payload.jti == jti and payload.sub == "alice"
        assert payload.token_type == kind

    @pytest.mark.parametrize("kind", TYPES)
    def test_claims_on_the_wire(self, kind, settings):
        token, jti = ISSUERS[kind]("alice", settings=settings)
        ttl = settings.access_ttl if kind == "access" else settings.refresh_ttl
        assert claims_of(token) == {
            "jti": jti,
            "sub": "alice",
            "iss": ISSUER,
            "aud": AUDIENCE,
            "iat": NOW,
            "nbf": NOW,
            "exp": NOW + ttl,
            "token_type": kind,
        }

    @pytest.mark.parametrize("kind", TYPES)
    def test_jti_is_a_uuid4_and_unique(self, kind, settings):
        jtis = {ISSUERS[kind]("alice", settings=settings)[1] for _ in range(50)}
        assert len(jtis) == 50
        for jti in jtis:
            assert uuid.UUID(jti).version == 4 and str(uuid.UUID(jti)) == jti

    @pytest.mark.parametrize("kind", TYPES)
    def test_custom_claims_roundtrip(self, kind, settings):
        custom = {
            "role": "admin",
            "scopes": ["a", "b"],
            "meta": {"n": 1, "ok": True, "x": None},
        }
        token, _ = ISSUERS[kind]("alice", custom, settings=settings)
        assert (
            parse_token(token, token_type=kind, settings=settings).custom_claims
            == custom
        )

    @pytest.mark.parametrize("kind", TYPES)
    def test_custom_claims_not_mutated(self, kind, settings):
        custom = {"role": "admin"}
        ISSUERS[kind]("alice", custom, settings=settings)
        assert custom == {"role": "admin"}

    @pytest.mark.parametrize("kind", TYPES)
    @pytest.mark.parametrize(
        "name", ["jti", "sub", "iat", "nbf", "exp", "iss", "aud", "token_type"]
    )
    def test_reserved_claims_cannot_be_overridden(self, kind, name, settings):
        with pytest.raises(InvalidPayload, match="reserved"):
            ISSUERS[kind]("alice", {name: "evil"}, settings=settings)

    @pytest.mark.parametrize("kind", TYPES)
    @pytest.mark.parametrize("sub", ["", "  ", None, 5, "bad uri:with space"])
    def test_invalid_subject(self, kind, sub, settings):
        with pytest.raises(InvalidPayload):
            ISSUERS[kind](sub, settings=settings)

    @pytest.mark.parametrize("kind", TYPES)
    def test_uses_environment_when_no_settings_given(self, kind, env):
        token, _ = ISSUERS[kind]("alice")
        assert parse_token(token, token_type=kind).sub == "alice"

    @pytest.mark.parametrize("kind", TYPES)
    def test_missing_environment(self, kind, no_env):
        with pytest.raises(InvalidSettings):
            ISSUERS[kind]("alice")

    @pytest.mark.parametrize("kind", TYPES)
    def test_header_is_hs_jwt_only(self, kind, settings):
        token, _ = ISSUERS[kind]("alice", settings=settings)
        assert json.loads(decode_part(split(token)[0])) == {
            "typ": "JWT",
            "alg": "HS256",
        }

    def test_refresh_outlives_access(self, settings):
        a, _ = issue_access_token("alice", settings=settings)
        r, _ = issue_refresh_token("alice", settings=settings)
        assert claims_of(r)["exp"] > claims_of(a)["exp"]


# ============================================================ parse_token: argument handling
class TestParseArguments:
    @pytest.mark.parametrize("token", [None, b"a.b.c", 1, ["a", "b", "c"]])
    def test_token_must_be_str(self, token, settings):
        with pytest.raises(TypeError, match="expected token type"):
            parse_token(token, token_type="access", settings=settings)

    @pytest.mark.parametrize("kind", ["id", "ACCESS", "", "Refresh", None, 1])
    def test_token_type_must_be_known(self, kind, settings):
        with pytest.raises(ValueError, match="invalid token_type"):
            parse_token("a.b.c", token_type=kind, settings=settings)

    def test_arguments_validated_before_settings_are_loaded(self, no_env):
        with pytest.raises(ValueError):
            parse_token("a.b.c", token_type="nope")
        with pytest.raises(TypeError):
            parse_token(None, token_type="access")

    def test_settings_loaded_from_env(self, env, clock):
        assert parse_token(forge(), token_type="access").sub == "user-1"

    def test_missing_env_raises_settings_error(self, no_env, clock):
        with pytest.raises(InvalidSettings):
            parse_token(forge(), token_type="access")

    def test_token_type_is_keyword_only(self, settings):
        with pytest.raises(TypeError):
            parse_token(forge(), "access", settings=settings)  # type: ignore[misc]


# ============================================================ parse_token: structure & signature
@pytest.mark.usefixtures("clock")
class TestParseStructure:
    @pytest.mark.parametrize(
        "token",
        [
            "",
            "a",
            "a.b",
            "a.b.c.d",
            ".b.c",
            "a..c",
            "a.b.",
            "..",
            "...",
            "a.b.c.",
            ".a.b.c",
        ],
    )
    def test_wrong_shape(self, token, settings):
        assert_rejected(token, TokenException, "malformed", settings)

    def test_malformed_signature_encoding(self, settings):
        h, p, _ = split(forge())
        for bad in ("***", "abc=", "a", "Zm9v\n", "é"):
            assert_rejected(
                f"{h}.{p}.{bad}", TokenException, "Malformed token signature", settings
            )

    def test_wrong_signature(self, settings):
        h, p, s = split(forge())
        flipped = ("A" if s[0] != "A" else "B") + s[1:]
        assert_rejected(
            f"{h}.{p}.{flipped}", TokenException, "Invalid signature", settings
        )

    def test_wrong_secret(self, settings):
        token = forge(secret=SECRET[::-1])
        assert_rejected(token, TokenException, "Invalid signature", settings)

    @pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
    def test_signature_checked_with_configured_algorithm(self, alg):
        s = make_settings(alg)
        token = forge({"typ": "JWT", "alg": alg}, sign_alg=alg)
        assert parse_token(token, token_type="access", settings=s).sub == "user-1"

    def test_signature_verified_before_anything_else_is_parsed(self, settings):
        # garbage header + garbage payload + bad signature -> only "Invalid signature"
        token = forge(b"\xff", b"\xfe", signature=b64(b"x" * 32))
        assert_rejected(token, TokenException, "Invalid signature", settings)

    def test_valid_token(self, settings):
        p = parse_token(forge(), token_type="access", settings=settings)
        assert p == Payload(
            jti="11111111-1111-4111-8111-111111111111",
            sub="user-1",
            iat=NOW,
            exp=NOW + 300,
            iss=ISSUER,
            aud=AUDIENCE,
            token_type="access",
            custom_claims={},
            nbf=NOW,
        )


# ============================================================ parse_token: header
def forge_raw(header_part: str, payload_part: str) -> str:
    return f"{header_part}.{payload_part}.{hs_sign(f'{header_part}.{payload_part}')}"


@pytest.mark.usefixtures("clock")
class TestParseHeader:
    def test_header_not_base64url(self, settings):
        token = forge_raw("@@@", b64(jdump(valid_claims())))
        assert_rejected(token, TokenException, "Malformed token header", settings)

    @pytest.mark.parametrize(
        "raw", [b"not json", b"\xff\xfe", b'{"alg":"HS256"', b"\xef\xbb\xbf{}"]
    )
    def test_header_not_json(self, raw, settings):
        assert_rejected(forge(raw), TokenException, "Malformed token header", settings)

    def test_header_duplicate_keys(self, settings):
        raw = b'{"alg":"none","alg":"HS256","typ":"JWT"}'
        assert_rejected(forge(raw), TokenException, "Malformed token header", settings)

    @pytest.mark.parametrize(
        "raw", [b"[]", b'"HS256"', b"1", b"null", b"true", b'["alg","HS256"]']
    )
    def test_header_not_object(self, raw, settings):
        assert_rejected(forge(raw), TokenException, "must be a JSON object", settings)

    @pytest.mark.parametrize(
        "alg",
        [
            None,
            256,
            ["HS256"],
            {"a": 1},
            True,
            "none",
            "None",
            "hs256",
            "HS256 ",
            "HS384",
            "HS512",
            "RS256",
            "ES256",
            "PS256",
            "",
        ],
    )
    def test_alg_must_equal_configured_algorithm(self, alg, settings):
        header = {"typ": "JWT", "alg": alg}
        assert_rejected(forge(header), TokenException, "'alg'", settings)

    def test_alg_missing(self, settings):
        assert_rejected(forge({"typ": "JWT"}), TokenException, "'alg'", settings)

    @pytest.mark.parametrize(
        "typ",
        ["JWT", "jwt", "Jwt", "application/jwt", "APPLICATION/JWT", "Application/Jwt"],
    )
    def test_typ_media_type_is_case_insensitive(self, typ, settings):
        token = forge({"alg": "HS256", "typ": typ})
        assert (
            parse_token(token, token_type="access", settings=settings).sub == "user-1"
        )

    def test_typ_is_optional(self, settings):
        assert parse_token(
            forge({"alg": "HS256"}), token_type="access", settings=settings
        )

    @pytest.mark.parametrize(
        "typ", ["JWS", "at+jwt", "jwt ", "", None, 1, ["JWT"], "application/json"]
    )
    def test_typ_invalid(self, typ, settings):
        assert_rejected(
            forge({"alg": "HS256", "typ": typ}), TokenException, "'typ'", settings
        )

    @pytest.mark.parametrize("cty", ["JWT", "jwt", "", None, 1])
    def test_cty_rejected(self, cty, settings):
        header = {"alg": "HS256", "typ": "JWT", "cty": cty}
        assert_rejected(forge(header), TokenException, "'cty'", settings)

    @pytest.mark.parametrize("crit", [["exp"], [], ["b64"], None, "x"])
    def test_crit_rejected(self, crit, settings):
        header = {"alg": "HS256", "typ": "JWT", "crit": crit}
        assert_rejected(forge(header), TokenException, "'crit'", settings)

    @pytest.mark.parametrize(
        "extra",
        [
            {"kid": "key-1"},
            {"x": 1},
            {"jku": "https://evil.example/k"},
            {"jwk": {"kty": "oct", "k": "AAAA"}},
            {"x5u": "https://e/x"},
        ],
    )
    def test_unknown_header_parameters_are_ignored(self, extra, settings):
        token = forge({"alg": "HS256", "typ": "JWT", **extra})
        assert (
            parse_token(token, token_type="access", settings=settings).sub == "user-1"
        )


# ============================================================ parse_token: payload
@pytest.mark.usefixtures("clock")
class TestParsePayload:
    def test_payload_not_base64url(self, settings):
        token = forge_raw(b64(jdump({"alg": "HS256", "typ": "JWT"})), "@@@")
        assert_rejected(token, InvalidPayload, "Malformed token payload", settings)

    @pytest.mark.parametrize(
        "raw",
        [
            b"not json",
            b"\xff",
            b'{"a":',
            b'{"sub":"a","sub":"b"}',
            b'{"exp":NaN}',
            b"\xef\xbb\xbf{}",
        ],
    )
    def test_payload_not_json(self, raw, settings):
        assert_rejected(
            forge(payload=raw), InvalidPayload, "Malformed token payload", settings
        )

    @pytest.mark.parametrize("raw", [b"[]", b'"x"', b"1", b"null", b"false", b"[{}]"])
    def test_payload_not_object(self, raw, settings):
        assert_rejected(
            forge(payload=raw), InvalidPayload, "must be a JSON object", settings
        )

    @pytest.mark.parametrize(
        "claim", ["jti", "sub", "iat", "exp", "iss", "aud", "token_type"]
    )
    def test_missing_required_claim(self, claim, settings):
        token = forge(payload=without(valid_claims(), claim))
        assert_rejected(token, InvalidPayload, f"Missing claims: {claim}", settings)

    def test_missing_claims_listed_sorted(self, settings):
        token = forge(payload=without(valid_claims(), "sub", "aud", "jti"))
        assert_rejected(
            token, InvalidPayload, "Missing claims: aud, jti, sub", settings
        )

    def test_empty_object_misses_everything(self, settings):
        assert_rejected(forge(payload={}), InvalidPayload, "Missing claims", settings)

    def test_nbf_null(self, settings):
        token = forge(payload=valid_claims(nbf=None))
        assert_rejected(token, InvalidPayload, "'nbf' must be an integer", settings)

    @pytest.mark.parametrize("nbf", ["1700000000", 1.5, True, [1], {"a": 1}, -1])
    def test_nbf_wrong_type(self, nbf, settings):
        assert_rejected(
            forge(payload=valid_claims(nbf=nbf)), InvalidPayload, "'nbf'", settings
        )

    @pytest.mark.parametrize("field", ["jti", "sub", "iss", "aud"])
    @pytest.mark.parametrize("value", [None, 1, True, ["x"], {"a": 1}, "", "  "])
    def test_string_claims_wrong_type(self, field, value, settings):
        token = forge(payload=valid_claims(**{field: value}))
        assert_rejected(token, InvalidPayload, field, settings)

    @pytest.mark.parametrize("value", [None, "refresh2", "ACCESS", 1, ["access"], ""])
    def test_token_type_claim_invalid(self, value, settings):
        token = forge(payload=valid_claims(token_type=value))
        with pytest.raises(TokenException):
            parse_token(token, token_type="access", settings=settings)

    @pytest.mark.parametrize(
        "value", [1.5, True, "1700000000", None, [1], {"a": 1}, -5]
    )
    def test_iat_wrong_type(self, value, settings):
        # RFC 7519 §2: NumericDate is a JSON number. A wrong type must be rejected as an
        # invalid payload, never crash with TypeError or be mistaken for another condition.
        token = forge(payload=valid_claims(iat=value))
        with pytest.raises(InvalidPayload):
            parse_token(token, token_type="access", settings=settings)

    @pytest.mark.parametrize(
        "value", [NOW + 300.5, True, "1700000300", None, [1], {"a": 1}]
    )
    def test_exp_wrong_type(self, value, settings):
        # same rule for "exp": the type check must come before any comparison with the clock
        token = forge(payload=valid_claims(exp=value))
        with pytest.raises(InvalidPayload):
            parse_token(token, token_type="access", settings=settings)

    def test_iat_after_exp(self, settings):
        token = forge(payload=valid_claims(iat=NOW + 1000, nbf=NOW, exp=NOW + 300))
        assert_rejected(
            token, InvalidPayload, "'exp' must be strictly greater", settings
        )

    def test_unknown_claims_preserved_as_custom_claims(self, settings):
        token = forge(
            payload=valid_claims(role="admin", nested={"a": [1, 2]}, flag=True)
        )
        p = parse_token(token, token_type="access", settings=settings)
        assert p.custom_claims == {
            "role": "admin",
            "nested": {"a": [1, 2]},
            "flag": True,
        }

    def test_unicode_claims(self, settings):
        token = forge(payload=valid_claims(sub="ユーザー", note="🙂"))
        p = parse_token(token, token_type="access", settings=settings)
        assert p.sub == "ユーザー" and p.custom_claims == {"note": "🙂"}


# ============================================================ parse_token: time and semantics
class TestParseTime:
    def test_not_expired_until_exp(self, clock, settings):
        token = forge()
        clock.now = NOW + 299
        assert parse_token(token, token_type="access", settings=settings)

    def test_expired_exactly_at_exp(self, clock, settings):
        token = forge()
        clock.now = NOW + 300
        assert_rejected(token, ExpiredToken, "expired", settings)

    def test_expired_after_exp(self, clock, settings):
        token = forge()
        clock.advance(10**6)
        assert_rejected(token, ExpiredToken, "expired", settings)

    def test_fractional_time_is_not_truncated(self, monkeypatch, settings):
        import time

        token = forge()
        monkeypatch.setattr(time, "time", lambda: NOW + 299.999)
        assert parse_token(token, token_type="access", settings=settings)
        monkeypatch.setattr(time, "time", lambda: NOW + 300.0)
        assert_rejected(token, ExpiredToken, "expired", settings)

    def test_expiry_wins_over_other_problems_in_signed_payload(self, clock, settings):
        token = forge(payload=valid_claims(sub="", iss="other"))
        clock.now = NOW + 301
        assert_rejected(token, ExpiredToken, "expired", settings)

    def test_not_before_in_future(self, clock, settings):
        token = forge(payload=valid_claims(nbf=NOW + 60))
        assert_rejected(token, TokenException, "not yet valid", settings)
        clock.now = NOW + 59
        assert_rejected(token, TokenException, "not yet valid", settings)

    def test_not_before_boundary_inclusive(self, clock, settings):
        token = forge(payload=valid_claims(nbf=NOW + 60))
        clock.now = NOW + 60
        assert parse_token(token, token_type="access", settings=settings)

    def test_nbf_is_optional_per_rfc7519_4_1_5(self, clock, settings):
        # RFC 7519 §4.1.5: "nbf" is OPTIONAL; Payload itself defaults it to iat
        token = forge(payload=without(valid_claims(), "nbf"))
        p = parse_token(token, token_type="access", settings=settings)
        assert p.nbf == p.iat


@pytest.mark.usefixtures("clock")
class TestParseSemantics:
    @pytest.mark.parametrize(
        ("issued", "expected"), [("access", "refresh"), ("refresh", "access")]
    )
    def test_token_type_confusion(self, issued, expected, settings):
        token, _ = ISSUERS[issued]("alice", settings=settings)
        assert_rejected(
            token,
            TokenException,
            f"expected a {expected} token, found {issued}",
            settings,
            token_type=expected,
        )

    @pytest.mark.parametrize(
        "iss", ["other", "TEST-ISSUER", "test-issuer ", "https://evil:1/"]
    )
    def test_wrong_issuer(self, iss, settings):
        token = forge(payload=valid_claims(iss=iss))
        assert_rejected(token, InvalidPayload, "unknown issuer", settings)

    @pytest.mark.parametrize(
        "aud", ["other", "TEST-AUDIENCE", "test-audience ", "https://evil:1/"]
    )
    def test_wrong_audience(self, aud, settings):
        token = forge(payload=valid_claims(aud=aud))
        assert_rejected(token, InvalidPayload, "unknown audience", settings)

    def test_audience_array_is_rejected(self, settings):
        # RFC 7519 allows an array, but this library only models a single string audience
        token = forge(payload=valid_claims(aud=[AUDIENCE]))
        assert_rejected(token, InvalidPayload, "aud", settings)

    def test_uri_issuer_and_audience(self):
        s = make_settings(issuer="https://issuer.example/", audience="urn:example:api")
        token = forge(
            payload=valid_claims(iss="https://issuer.example/", aud="urn:example:api")
        )
        assert (
            parse_token(token, token_type="access", settings=s).iss
            == "https://issuer.example/"
        )


# ============================================================ verify_token
@pytest.mark.usefixtures("clock")
class TestVerifyToken:
    @pytest.mark.parametrize("kind", TYPES)
    def test_true_for_valid_tokens(self, kind, settings):
        token, _ = ISSUERS[kind]("alice", settings=settings)
        assert verify_token(token, token_type=kind, settings=settings) is True

    @pytest.mark.parametrize(
        "token", ["", "a.b.c", "x", "a.b", None, 1, b"a.b.c", ["a"]]
    )
    def test_false_for_garbage(self, token, settings):
        assert verify_token(token, token_type="access", settings=settings) is False

    def test_false_for_wrong_type(self, settings):
        token, _ = issue_refresh_token("alice", settings=settings)
        assert verify_token(token, token_type="access", settings=settings) is False

    def test_false_for_expired(self, clock, settings):
        token = forge()
        clock.advance(301)
        assert verify_token(token, token_type="access", settings=settings) is False

    def test_false_for_bad_signature(self, settings):
        assert (
            verify_token(
                forge(secret=SECRET[::-1]), token_type="access", settings=settings
            )
            is False
        )

    def test_false_for_invalid_token_type_argument(self, settings):
        assert verify_token(forge(), token_type="bogus", settings=settings) is False  # type: ignore[arg-type]

    def test_loads_settings_from_env(self, env):
        assert verify_token(forge(), token_type="access") is True

    def test_misconfiguration_is_not_reported_as_invalid_token(self, no_env):
        with pytest.raises(InvalidSettings):
            verify_token(forge(), token_type="access")

    @pytest.mark.parametrize("exp", ["9999999999", None, [1], {"a": 1}])
    def test_never_raises_for_signed_junk_claims(self, exp, settings):
        token = forge(payload=valid_claims(exp=exp))
        assert verify_token(token, token_type="access", settings=settings) is False


# ============================================================ renew_access_token
class TestRenew:
    def test_issues_a_valid_access_token(self, clock, settings):
        refresh, _ = issue_refresh_token("alice", {"role": "admin"}, settings=settings)
        clock.advance(100)
        access, jti = renew_access_token(refresh, settings=settings)
        p = parse_token(access, token_type="access", settings=settings)
        assert (
            p.jti == jti and p.sub == "alice" and p.custom_claims == {"role": "admin"}
        )
        assert p.iat == NOW + 100 and p.exp == NOW + 100 + settings.access_ttl
        assert p.iss == ISSUER and p.aud == AUDIENCE and p.token_type == "access"

    def test_new_jti_each_time(self, clock, settings):
        refresh, refresh_jti = issue_refresh_token("alice", settings=settings)
        jtis = {renew_access_token(refresh, settings=settings)[1] for _ in range(20)}
        assert len(jtis) == 20 and refresh_jti not in jtis

    def test_access_token_cannot_outlive_refresh_token(self, clock, settings):
        refresh, _ = issue_refresh_token("alice", settings=settings)
        refresh_exp = claims_of(refresh)["exp"]
        clock.now = refresh_exp - 10  # only 10s left, access_ttl is 300s
        access, _ = renew_access_token(refresh, settings=settings)
        assert claims_of(access)["exp"] == refresh_exp

    def test_exp_is_min_when_refresh_has_plenty_left(self, clock, settings):
        refresh, _ = issue_refresh_token("alice", settings=settings)
        access, _ = renew_access_token(refresh, settings=settings)
        assert claims_of(access)["exp"] == NOW + settings.access_ttl

    def test_last_second_of_refresh_token(self, clock, settings):
        refresh, _ = issue_refresh_token("alice", settings=settings)
        clock.now = claims_of(refresh)["exp"] - 1
        access, _ = renew_access_token(refresh, settings=settings)
        assert claims_of(access)["exp"] == clock.now + 1

    def test_expired_refresh_token(self, clock, settings):
        refresh, _ = issue_refresh_token("alice", settings=settings)
        clock.advance(settings.refresh_ttl)
        with pytest.raises(TokenException, match="invalid refresh token"):
            renew_access_token(refresh, settings=settings)

    def test_access_token_is_not_a_refresh_token(self, clock, settings):
        access, _ = issue_access_token("alice", settings=settings)
        with pytest.raises(TokenException, match="invalid refresh token"):
            renew_access_token(access, settings=settings)

    @pytest.mark.parametrize("token", ["", "a.b.c", None, 5, b"a.b.c"])
    def test_garbage(self, token, clock, settings):
        with pytest.raises(TokenException, match="invalid refresh token"):
            renew_access_token(token, settings=settings)

    def test_tampered_refresh_token(self, clock, settings):
        refresh, _ = issue_refresh_token("alice", settings=settings)
        h, p, s = split(refresh)
        evil = b64(jdump({**claims_of(refresh), "sub": "admin"}))
        with pytest.raises(TokenException, match="invalid refresh token"):
            renew_access_token(f"{h}.{evil}.{s}", settings=settings)

    def test_loads_settings_from_env(self, clock, env):
        refresh, _ = issue_refresh_token("alice")
        access, _ = renew_access_token(refresh)
        assert parse_token(access, token_type="access").sub == "alice"

    def test_missing_env(self, clock, no_env):
        with pytest.raises(InvalidSettings):
            renew_access_token("a.b.c")
