import base64
import binascii
import hashlib
import hmac
import json

import pytest

from easy_jwt import utils
from easy_jwt.settings import JWTSettings
from easy_jwt.utils import (
    RESERVED_CLAIMS,
    generate_token,
    json_decoder,
    url_decoder,
)

from .helpers import B64URL_ALPHABET, SECRET, b64, decode_part, split


def test_reserved_claims():
    assert RESERVED_CLAIMS == {
        "jti",
        "sub",
        "iat",
        "nbf",
        "exp",
        "iss",
        "aud",
        "token_type",
    }


# ---------------------------------------------------------------- url_decoder
class TestUrlDecoder:
    @pytest.mark.parametrize(
        "data",
        [b"", b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar", bytes(range(256))],
    )
    def test_roundtrip(self, data):
        assert url_decoder(b64(data)) == data

    @pytest.mark.parametrize(
        ("encoded", "expected"),
        [
            ("", b""),
            ("Zg", b"f"),
            ("Zm8", b"fo"),
            ("Zm9v", b"foo"),
            ("Zm9vYg", b"foob"),
            ("Zm9vYmE", b"fooba"),
            ("Zm9vYmFy", b"foobar"),
        ],
    )  # RFC 4648 §10 vectors, unpadded
    def test_rfc4648_vectors(self, encoded, expected):
        assert url_decoder(encoded) == expected

    def test_url_safe_alphabet_is_used(self):
        assert url_decoder("A-z_4ME") == bytes(
            [3, 236, 255, 224, 193]
        )  # RFC 7515 App. C

    @pytest.mark.parametrize("value", [None, 1, b"Zg", ["Zg"]])
    def test_non_str(self, value):
        with pytest.raises(TypeError):
            url_decoder(value)

    @pytest.mark.parametrize(
        "value",
        [
            "Zg==",
            "Zm9v=",
            "Z g",
            "Zm9v\n",
            "\nZm9v",
            " Zm9v",
            "Zm+/",
            "Zm9v.",
            "Zé",
            "Z\x00g",
            "Zm9v\u2028",
            "Ｚｍ９ｖ",
        ],
    )
    def test_rejects_non_alphabet_characters(self, value):
        with pytest.raises(ValueError, match="Invalid base64url characters"):
            url_decoder(value)

    @pytest.mark.parametrize("value", ["A", "Zm9vY", "AAAAA", "A" * 101])
    def test_rejects_impossible_length(self, value):
        with pytest.raises(ValueError, match="length"):
            url_decoder(value)

    @pytest.mark.parametrize("value", ["QR", "QUJ", "Zh", "Zm9", "AB", "A-z_4MF"])
    def test_rejects_non_canonical_trailing_bits(self, value):
        # "QR" and "QQ" would both decode to b"A" in a lenient decoder (malleability)
        with pytest.raises(ValueError, match="Non-canonical"):
            url_decoder(value)

    def test_canonical_form_is_unique(self):
        assert url_decoder("QQ") == b"A"
        with pytest.raises(ValueError):
            url_decoder("QR")

    def test_every_non_canonical_last_char_is_rejected(self):
        for data in (b"A", b"AB"):
            canonical = b64(data)
            last = B64URL_ALPHABET.index(canonical[-1])
            mask = 0x0F if len(data) == 1 else 0x03
            for variant in range(1, mask + 1):
                forged = canonical[:-1] + B64URL_ALPHABET[last | variant]
                with pytest.raises(ValueError):
                    url_decoder(forged)

    def test_binascii_error_is_wrapped(self, monkeypatch):
        def boom(_):
            raise binascii.Error("boom")

        monkeypatch.setattr(base64, "urlsafe_b64decode", boom)
        with pytest.raises(ValueError, match="Invalid base64url encoding"):
            url_decoder("Zm9v")


# ---------------------------------------------------------------- json_decoder
class TestJsonDecoder:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ('{"a": 1}', {"a": 1}),
            ('[1, 2.5, null, true, false, "x"]', [1, 2.5, None, True, False, "x"]),
            ("1", 1),
            ("-0", 0),
            ('"é"', "é"),
            ('"\\ud83d\\ude00"', "😀"),  # valid surrogate PAIR is fine
            ('{"a": {"b": [{"c": 1}]}}', {"a": {"b": [{"c": 1}]}}),
            (
                ' \r\n {"a":1} \t',
                {"a": 1},
            ),  # insignificant whitespace (RFC 7515 App. A.1)
        ],
    )
    def test_accepts_str_bytes_bytearray(self, text, expected):
        assert json_decoder(text) == expected
        assert json_decoder(text.encode()) == expected
        assert json_decoder(bytearray(text.encode())) == expected

    @pytest.mark.parametrize("value", [None, 1, 1.5, ["{}"], {"a": 1}, object()])
    def test_wrong_input_type(self, value):
        with pytest.raises(TypeError, match="expected bytes"):
            json_decoder(value)

    @pytest.mark.parametrize(
        "data", [b"\xff", b'{"a":"\xc3"}', b"\xed\xa0\x80", b"\xc0\xaf"]
    )
    def test_invalid_utf8(self, data):
        with pytest.raises(ValueError):
            json_decoder(data)

    def test_bom_rejected(self):
        with pytest.raises(ValueError):
            json_decoder(b"\xef\xbb\xbf{}")
        with pytest.raises(ValueError):
            json_decoder("\ufeff{}")

    @pytest.mark.parametrize(
        "text",
        [
            "",
            " ",
            "{",
            '{"a":1}}',
            "{'a':1}",
            '{"a":1,}',
            "nul",
            '{"a":1} {"b":2}',
            "01",
            ".5",
            "+1",
        ],
    )
    def test_malformed_json(self, text):
        with pytest.raises(ValueError):
            json_decoder(text)

    @pytest.mark.parametrize(
        "text", ["NaN", "Infinity", "-Infinity", '{"a": NaN}', "[Infinity]"]
    )
    def test_non_finite_constants_rejected(self, text):
        with pytest.raises(ValueError, match="Non-finite JSON constant"):
            json_decoder(text)

    @pytest.mark.parametrize("text", ["1e999", "-1e999", '{"a": 1E400}'])
    def test_float_overflow_to_infinity_rejected(self, text):
        with pytest.raises(ValueError, match="Non-finite JSON float"):
            json_decoder(text)

    def test_finite_floats_allowed(self):
        assert json_decoder("1.5e3") == 1500.0
        assert json_decoder("-2.25") == -2.25

    def test_integer_digit_limit(self):
        assert len(str(json_decoder("1" * 4300))) == 4300
        assert len(str(json_decoder("-" + "1" * 4300))) == 4301
        with pytest.raises(ValueError, match="exceeds maximum"):
            json_decoder("1" * 4301)
        with pytest.raises(ValueError, match="exceeds maximum"):
            json_decoder("-" + "1" * 4301)
        with pytest.raises(ValueError, match="exceeds maximum"):
            json_decoder('{"exp": ' + "9" * 10_000 + "}")

    @pytest.mark.parametrize(
        "text",
        [
            '{"a":1,"a":2}',
            '{"a":1,"b":2,"a":1}',
            '{"x":{"a":1,"a":2}}',
            '[{"a":1,"a":1}]',
        ],
    )
    def test_duplicate_keys_rejected(self, text):
        with pytest.raises(ValueError, match="Duplicate JSON key"):
            json_decoder(text)

    def test_duplicate_detection_is_after_unescaping(self):
        with pytest.raises(ValueError, match="Duplicate"):
            json_decoder('{"a":1,"\\u0061":2}')

    @pytest.mark.parametrize(
        "text",
        [
            '"\\ud800"',
            '"\\udc00"',
            '"\\udc00\\ud800"',
            '{"\\ud800": 1}',
            '["ok", "\\udfff"]',
            '{"a": {"b": ["\\ud800"]}}',
            '{"a": [{"b": "x\\ud800y"}]}',
        ],
    )
    def test_lone_surrogates_rejected(self, text):
        with pytest.raises(ValueError):
            json_decoder(text)

    def test_raw_lone_surrogate_str_rejected(self):
        with pytest.raises(ValueError):
            json_decoder('"\ud800"')

    def test_deep_nesting_becomes_value_error(self):
        for opener, closer in (("[", "]"), ('{"a":', "}")):
            with pytest.raises(ValueError, match="nesting depth"):
                json_decoder(opener * 200_000 + "1" + closer * 200_000)


# ---------------------------------------------------------------- generate_token
class TestGenerateToken:
    @pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
    def test_structure_and_signature(self, alg):
        settings = JWTSettings(
            secret=SECRET,
            access_ttl=300,
            refresh_ttl=600,
            issuer="i",
            audience="a",
            algorithm=alg,
        )
        token = generate_token({"sub": "x", "n": 1}, settings)
        h, p, s = split(token)
        assert "=" not in token
        assert json.loads(decode_part(h)) == {"typ": "JWT", "alg": alg}
        assert json.loads(decode_part(p)) == {"sub": "x", "n": 1}
        digest = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }[alg]
        expected = hmac.new(SECRET.encode(), f"{h}.{p}".encode(), digest).digest()
        assert decode_part(s) == expected
        assert len(expected) == {"HS256": 32, "HS384": 48, "HS512": 64}[alg]

    def test_output_is_canonical_base64url(self, settings):
        for claims in ({}, {"a": "é" * 7}, {"k": "?>~" * 11}):
            for part in generate_token(claims, settings).split("."):
                assert url_decoder(part) == decode_part(part)

    def test_non_serializable_payload_raises(self, settings):
        with pytest.raises(TypeError):
            generate_token({"x": object()}, settings)

    def test_different_secret_gives_different_signature(self, settings):
        other = JWTSettings(
            secret=SECRET[::-1],
            access_ttl=300,
            refresh_ttl=600,
            issuer="i",
            audience="a",
            algorithm="HS256",
        )
        a = generate_token({"a": 1}, settings).split(".")[2]
        b = generate_token({"a": 1}, other).split(".")[2]
        assert a != b


def test_module_level_helpers_are_private_api():
    # guard against accidental removal of the decoder helpers used by parse_token
    for name in ("json_decoder", "url_decoder", "generate_token", "RESERVED_CLAIMS"):
        assert hasattr(utils, name)
