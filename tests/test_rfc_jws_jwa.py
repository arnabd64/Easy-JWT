"""RFC 7515 (JWS) and RFC 7518 (JWA) conformance."""

import hashlib
import hmac
import json

import pytest

from easy_jwt import JWTSettings, parse_token
from easy_jwt.exceptions import InvalidSettings, TokenException
from easy_jwt.utils import generate_token, json_decoder, url_decoder

from .helpers import SECRET, b64, decode_part, forge, hs_sign, split

# RFC 7515 Appendix A.1: JWS using HMAC SHA-256 (the published example, verbatim)
A1_HEADER = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
A1_PAYLOAD = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
A1_SIGNATURE = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
A1_KEY = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"


class TestRfc7515:
    def test_appendix_a1_parts_decode_with_the_library_decoders(self):
        # The example uses CRLF + space pretty-printing: JSON whitespace must be tolerated
        assert json_decoder(url_decoder(A1_HEADER)) == {"typ": "JWT", "alg": "HS256"}
        assert json_decoder(url_decoder(A1_PAYLOAD)) == {
            "iss": "joe",
            "exp": 1300819380,
            "http://example.com/is_root": True,
        }

    def test_appendix_a1_signature_is_a_32_byte_hmac_sha256(self):
        key = url_decoder(A1_KEY)
        expected = hmac.new(
            key, f"{A1_HEADER}.{A1_PAYLOAD}".encode(), hashlib.sha256
        ).digest()
        assert url_decoder(A1_SIGNATURE) == expected

    def test_appendix_c_base64url_vector(self):
        # RFC 7515 Appendix C: octets 3,236,255,224,193 -> "A-z_4ME"
        assert url_decoder("A-z_4ME") == bytes([3, 236, 255, 224, 193])

    def test_compact_serialization_has_three_dot_separated_parts(self, settings):
        token = generate_token({"a": 1}, settings)
        assert token.count(".") == 2 and all(token.split("."))

    def test_signing_input_is_ascii_header_dot_payload(self, settings):
        # §5.1: signature = HMAC(ASCII(BASE64URL(header) || '.' || BASE64URL(payload)))
        h, p, s = split(generate_token({"a": 1}, settings))
        expected = hmac.new(
            SECRET.encode(), f"{h}.{p}".encode("ascii"), hashlib.sha256
        ).digest()
        assert decode_part(s) == expected

    def test_no_base64_padding_anywhere(self, settings):
        # §2: base64url "with all trailing '=' characters omitted"
        assert "=" not in generate_token({"a": "x" * 5}, settings)

    def test_header_has_alg_parameter_mandatory_per_4_1_1(self, settings):
        header = json.loads(decode_part(split(generate_token({}, settings))[0]))
        assert header["alg"] == "HS256"

    def test_alg_is_required_on_parse(self, clock, settings):
        with pytest.raises(TokenException, match="'alg'"):
            parse_token(forge({"typ": "JWT"}), token_type="access", settings=settings)

    def test_crit_present_must_be_rejected_when_unsupported(self, clock, settings):
        # §4.1.11: implementations MUST reject a JWS carrying crit extensions they do not understand
        with pytest.raises(TokenException, match="crit"):
            parse_token(
                forge({"alg": "HS256", "crit": ["exp"], "exp": 1}),
                token_type="access",
                settings=settings,
            )

    def test_duplicate_header_names_are_rejected(self, clock, settings):
        # §4: Header Parameter names MUST be unique (JSON members with duplicate names are not allowed)
        raw = b'{"alg":"HS256","alg":"HS256"}'
        with pytest.raises(TokenException, match="Malformed token header"):
            parse_token(forge(raw), token_type="access", settings=settings)

    def test_header_must_be_a_json_object(self, clock, settings):
        with pytest.raises(TokenException, match="JSON object"):
            parse_token(
                forge(b'["alg","HS256"]'), token_type="access", settings=settings
            )

    def test_signature_is_validated_over_the_exact_received_bytes(
        self, clock, settings
    ):
        # Re-serialising (e.g. reordering/whitespace) must not be needed: signature covers raw text
        header = b'{ "typ" : "JWT", "alg" : "HS256" }'
        assert parse_token(forge(header), token_type="access", settings=settings)

    def test_non_canonical_encoding_of_any_part_is_rejected(self, clock, settings):
        h, p, s = split(forge())
        with pytest.raises(TokenException):
            parse_token(
                f"{h}.{p}.{s}=", token_type="access", settings=settings
            )  # padded


class TestRfc7518:
    @pytest.mark.parametrize(
        ("alg", "size"), [("HS256", 32), ("HS384", 48), ("HS512", 64)]
    )
    def test_section_3_2_key_must_be_at_least_hash_output_size(self, alg, size):
        with pytest.raises(InvalidSettings):
            JWTSettings(
                secret=SECRET[: size - 1],
                access_ttl=30,
                refresh_ttl=60,
                issuer="i",
                audience="a",
                algorithm=alg,
            )
        JWTSettings(
            secret=SECRET[:size],
            access_ttl=30,
            refresh_ttl=60,
            issuer="i",
            audience="a",
            algorithm=alg,
        )

    @pytest.mark.parametrize(
        ("alg", "digest", "length"),
        [
            ("HS256", hashlib.sha256, 32),
            ("HS384", hashlib.sha384, 48),
            ("HS512", hashlib.sha512, 64),
        ],
    )
    def test_hmac_sha2_algorithms_and_output_lengths(self, alg, digest, length):
        s = JWTSettings(
            secret=SECRET,
            access_ttl=30,
            refresh_ttl=60,
            issuer="i",
            audience="a",
            algorithm=alg,
        )
        h, p, sig = split(generate_token({"a": 1}, s))
        assert json.loads(decode_part(h))["alg"] == alg
        assert len(decode_part(sig)) == length
        assert (
            decode_part(sig)
            == hmac.new(SECRET.encode(), f"{h}.{p}".encode(), digest).digest()
        )

    @pytest.mark.parametrize(
        "alg", ["none", "RS256", "ES256", "PS256", "EdDSA", "HS1", "HS224", "HS999"]
    )
    def test_only_hmac_sha2_family_is_supported(self, alg):
        with pytest.raises(InvalidSettings):
            JWTSettings(
                secret=SECRET,
                access_ttl=30,
                refresh_ttl=60,
                issuer="i",
                audience="a",
                algorithm=alg,
            )  # type: ignore[arg-type]

    def test_algorithm_identifiers_are_case_sensitive(self):
        with pytest.raises(InvalidSettings):
            JWTSettings(
                secret=SECRET,
                access_ttl=30,
                refresh_ttl=60,
                issuer="i",
                audience="a",
                algorithm="hs256",
            )  # type: ignore[arg-type]

    def test_hmac_comparison_is_over_full_digest_no_truncation(self, clock, settings):
        h, p, s = split(forge())
        half = b64(decode_part(s)[:16])
        with pytest.raises(TokenException, match="Invalid signature"):
            parse_token(f"{h}.{p}.{half}", token_type="access", settings=settings)

    def test_helper_signature_matches_reference_hmac(self):
        # sanity check of the test helper itself, so forged tokens in other files are trustworthy
        assert hs_sign("a.b") == b64(
            hmac.new(SECRET.encode(), b"a.b", hashlib.sha256).digest()
        )
