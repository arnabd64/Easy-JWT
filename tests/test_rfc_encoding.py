"""RFC 4648 (base64url), RFC 8259 (JSON) and RFC 3986 (URI) behaviour the JWT layer relies on."""

import json

import pytest

from easy_jwt.exceptions import InvalidPayload, InvalidSettings
from easy_jwt.payload import Payload
from easy_jwt.utils import json_decoder, url_decoder

from .helpers import B64URL_ALPHABET, NOW, b64, make_settings


class TestRfc4648:
    def test_section_5_url_safe_alphabet_replaces_plus_and_slash(self):
        assert url_decoder("-_") == b"\xfb"
        for ch in "+/":
            with pytest.raises(ValueError):
                url_decoder("AA" + ch + "A")

    def test_section_3_5_canonical_encoding(self):
        # non-zero pad bits are a malleability vector; the decoder must reject them
        with pytest.raises(ValueError, match="Non-canonical"):
            url_decoder("Zh")

    def test_section_3_3_non_alphabet_characters_are_rejected_not_skipped(self):
        # lenient decoders silently drop line breaks/whitespace: that must not happen here
        for bad in ("Zm9v\r\n", "Zm 9v", "Zm9v\t", "\x00Zm9v"):
            with pytest.raises(ValueError):
                url_decoder(bad)

    def test_unpadded_form_only(self):
        with pytest.raises(ValueError):
            url_decoder("Zg==")
        assert url_decoder("Zg") == b"f"

    def test_whole_alphabet_decodes(self):
        data = url_decoder(B64URL_ALPHABET)
        assert b64(data) == B64URL_ALPHABET


class TestRfc8259:
    def test_section_8_1_utf8_only(self):
        assert json_decoder('"é"'.encode("utf-8")) == "é"
        with pytest.raises(ValueError):
            json_decoder('"é"'.encode("utf-16"))
        with pytest.raises(ValueError):
            json_decoder('"é"'.encode("latin-1"))

    def test_section_8_1_bom_must_not_be_added(self):
        with pytest.raises(ValueError):
            json_decoder(b"\xef\xbb\xbf" + b'{"a":1}')

    def test_section_8_2_unpaired_surrogates_are_rejected(self):
        with pytest.raises(ValueError):
            json_decoder('{"sub":"\\ud800"}')
        assert json_decoder('"\\ud834\\udd1e"') == "\U0001d11e"  # a proper pair is fine

    def test_section_4_duplicate_member_names(self):
        # RFC 8259 only says names SHOULD be unique (behaviour otherwise unpredictable);
        # RFC 7519 §4 says MUST for claim names. We follow the strict rule.
        with pytest.raises(ValueError):
            json_decoder('{"a":1,"a":2}')

    def test_section_6_numbers_nan_and_infinity_are_not_json(self):
        for text in ("NaN", "Infinity", "-Infinity"):
            with pytest.raises(ValueError):
                json_decoder(text)

    def test_section_6_leading_zeros_and_plus_are_not_json(self):
        for text in ("01", "+1", ".5", "1.", "0x10"):
            with pytest.raises(ValueError):
                json_decoder(text)

    def test_section_9_parsers_may_limit_nesting(self):
        with pytest.raises(ValueError):
            json_decoder("[" * 100_000 + "]" * 100_000)

    def test_section_2_insignificant_whitespace(self):
        assert json_decoder(b' \t\r\n{ "a" :\n1 } \n') == {"a": 1}

    def test_standard_library_agrees_on_valid_documents(self):
        doc = {"a": [1, 2.5, None, True, "x"], "b": {"c": "é"}}
        assert json_decoder(json.dumps(doc)) == doc


class TestRfc3986:
    @pytest.mark.parametrize(
        "uri", ["https://a.example/p?q#f", "urn:a:b", "mailto:x@y.z", "a+b-c.d:e"]
    )
    def test_valid_uris_in_claims_and_settings(self, uri):
        assert make_settings(issuer=uri).issuer == uri
        assert (
            Payload(
                jti="j",
                sub=uri,
                iat=NOW - 5,
                exp=NOW + 5**20,
                iss="i",
                aud="a",
                token_type="access",
            ).sub
            == uri
        )

    @pytest.mark.parametrize(
        "uri",
        [
            "a b:c",
            "a:%zz",
            "a:<b>",
            'a:"b"',
            "a:{b}",
            "a:\\b",
            "a:^b",
            "a:`b",
            "a:|b",
            "http://h:70000",
            "9a:b",
            "http:",
            "a:\x7f",
        ],
    )
    def test_invalid_uris_are_rejected_everywhere(self, uri, clock):
        with pytest.raises(InvalidSettings):
            make_settings(issuer=uri)
        with pytest.raises(InvalidPayload):
            Payload(
                jti="j",
                sub=uri,
                iat=NOW,
                exp=NOW + 100,
                iss="i",
                aud="a",
                token_type="access",
            )
