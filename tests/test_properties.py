"""Property-based tests (hypothesis). No fixtures: these run against the real clock with long TTLs."""

import json
import math
import string
import time

import pytest
from hypothesis import assume, example, given
from hypothesis import strategies as st

from easy_jwt import (
    issue_access_token,
    issue_refresh_token,
    parse_token,
    renew_access_token,
    verify_token,
)
from easy_jwt.exceptions import InvalidPayload, InvalidSettings, TokenException
from easy_jwt.payload import Payload
from easy_jwt.settings import JWTSettings, shannon_entropy
from easy_jwt.utils import RESERVED_CLAIMS, json_decoder, url_decoder

from .helpers import B64URL_ALPHABET, SECRET, b64, forge, make_settings, valid_claims

S = make_settings(access_ttl=300, refresh_ttl=3600)
ISSUERS = {"access": issue_access_token, "refresh": issue_refresh_token}

# ---------------------------------------------------------------- strategies
json_scalars = (
    st.none()
    | st.booleans()
    | st.integers(-(2**53), 2**53)
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text()
)
json_values = st.recursive(
    json_scalars,
    lambda children: (
        st.lists(children, max_size=4)
        | st.dictionaries(st.text(), children, max_size=4)
    ),
    max_leaves=12,
)
subjects = st.text(
    alphabet=string.ascii_letters + string.digits + "-_.", min_size=1, max_size=40
)
claim_names = st.text(min_size=1, max_size=20).filter(
    lambda k: k.strip() != "" and k not in RESERVED_CLAIMS
)
custom_claims = st.dictionaries(claim_names, json_values, max_size=5)
registered_names = sorted(RESERVED_CLAIMS)


# ---------------------------------------------------------------- url_decoder
@given(st.binary(max_size=300))
def test_base64url_roundtrip(data):
    assert url_decoder(b64(data)) == data


@given(st.text(max_size=200))
@example("QR")
@example("Zm9v\n")
def test_url_decoder_only_accepts_canonical_input(text):
    try:
        decoded = url_decoder(text)
    except ValueError:
        return
    assert b64(decoded) == text  # accepted => it was the one canonical encoding


@given(st.text(alphabet=B64URL_ALPHABET, max_size=200))
def test_url_decoder_on_alphabet_text_never_raises_unexpectedly(text):
    try:
        url_decoder(text)
    except ValueError:
        pass


# ---------------------------------------------------------------- json_decoder
@given(json_values)
def test_json_roundtrip(value):
    assert json_decoder(json.dumps(value)) == value
    assert json_decoder(json.dumps(value).encode()) == value


@given(st.binary(max_size=200))
def test_json_decoder_raises_only_value_error_on_arbitrary_bytes(data):
    try:
        json_decoder(data)
    except ValueError:
        pass


@given(st.text(max_size=200))
def test_json_decoder_raises_only_value_error_on_arbitrary_text(text):
    try:
        json_decoder(text)
    except ValueError:
        pass


# ---------------------------------------------------------------- settings
@given(st.text(max_size=100))
def test_entropy_bounds_and_permutation_invariance(text):
    h = shannon_entropy(text)
    assert h >= 0
    assert h <= math.log2(max(len(set(text)), 1)) + 1e-9
    assert shannon_entropy(text[::-1]) == pytest.approx(h)


@given(access=st.integers(30, 10**6), extra=st.integers(0, 10**6))
def test_valid_ttl_pairs_accepted(access, extra):
    refresh = max(60, access) + extra
    s = make_settings(access_ttl=access, refresh_ttl=refresh)
    assert (s.access_ttl, s.refresh_ttl) == (access, refresh)


@given(access=st.integers(60, 10**6), shortfall=st.integers(1, 1000))
def test_refresh_shorter_than_access_rejected(access, shortfall):
    refresh = access - shortfall
    assume(refresh >= 60)
    with pytest.raises(InvalidSettings):
        make_settings(access_ttl=access, refresh_ttl=refresh)


@given(st.text(max_size=60))
def test_issuer_validation_only_raises_invalid_settings(value):
    try:
        make_settings(issuer=value)
    except InvalidSettings:
        pass


@given(st.text(max_size=60))
def test_payload_validation_only_raises_invalid_payload(value):
    now = int(time.time())
    try:
        Payload(
            jti="j",
            sub=value,
            iat=now,
            exp=now + 100,
            iss="i",
            aud="a",
            token_type="access",
        )
    except InvalidPayload:
        pass


@given(st.integers(0, 10**4), st.integers(60, 10**6), st.integers(0, 10**4))
def test_payload_accepts_ordered_times(back, ahead, nbf_back):
    now = int(time.time())
    iat = max(now - back, 0)
    nbf = max(iat - nbf_back, 0)
    p = Payload(
        jti="j",
        sub="s",
        iat=iat,
        exp=now + ahead,
        iss="i",
        aud="a",
        token_type="refresh",
        nbf=nbf,
    )
    flat = p.flatten_claims()
    assert flat["iat"] == iat and flat["nbf"] == nbf and flat["exp"] == now + ahead


@given(st.integers(0, 10**4), st.integers(0, 10**4))
def test_payload_rejects_exp_not_after_iat(offset, drop):
    now = int(time.time())
    iat = now + offset
    with pytest.raises(InvalidPayload):
        Payload(
            jti="j",
            sub="s",
            iat=iat,
            exp=iat - drop,
            iss="i",
            aud="a",
            token_type="access",
            nbf=0,
        )


# ---------------------------------------------------------------- issue / parse
@pytest.mark.parametrize("kind", ["access", "refresh"])
@given(sub=subjects, custom=custom_claims)
def test_issue_then_parse_roundtrip(kind, sub, custom):
    token, jti = ISSUERS[kind](sub, custom, settings=S)
    payload = parse_token(token, token_type=kind, settings=S)
    assert payload.sub == sub and payload.jti == jti
    assert payload.custom_claims == custom
    assert verify_token(token, token_type=kind, settings=S) is True


@given(sub=subjects, custom=custom_claims)
def test_renew_preserves_subject_and_claims(sub, custom):
    refresh, _ = issue_refresh_token(sub, custom, settings=S)
    access, _ = renew_access_token(refresh, settings=S)
    payload = parse_token(access, token_type="access", settings=S)
    assert payload.sub == sub and payload.custom_claims == custom


@given(st.data())
def test_any_single_character_mutation_invalidates_a_token(data):
    token, _ = issue_refresh_token("alice", {"k": "v"}, settings=S)
    i = data.draw(st.integers(0, len(token) - 1))
    replacement = data.draw(st.sampled_from(B64URL_ALPHABET + ".=+/ \n"))
    assume(replacement != token[i])
    mutated = token[:i] + replacement + token[i + 1 :]
    assert verify_token(mutated, token_type="refresh", settings=S) is False


@given(st.text(max_size=300))
def test_verify_token_never_raises_and_rejects_arbitrary_text(text):
    assert verify_token(text, token_type="access", settings=S) is False


@given(
    st.from_regex(
        r"[A-Za-z0-9_-]{0,60}\.[A-Za-z0-9_-]{0,60}\.[A-Za-z0-9_-]{0,60}", fullmatch=True
    )
)
def test_verify_token_rejects_well_shaped_but_unsigned_tokens(text):
    assert verify_token(text, token_type="refresh", settings=S) is False


header_extras = st.dictionaries(
    st.sampled_from(["typ", "cty", "crit", "kid", "jwk", "jku", "b64"]),
    json_values,
    max_size=4,
)
headers = header_extras.map(lambda extra: {"alg": "HS256", **extra})
claim_overrides = st.dictionaries(
    st.sampled_from(registered_names), json_values, max_size=3
)


@given(header=headers, overrides=claim_overrides)
def test_correctly_signed_junk_only_ever_raises_token_exceptions(header, overrides):
    # Whatever is inside a *validly signed* token, the library must either return a Payload or raise
    # one of its own TokenException subclasses; never TypeError/KeyError/RecursionError etc.
    claims = {**valid_claims(now=int(time.time())), **overrides}
    token = forge(header=header, payload=claims)
    try:
        payload = parse_token(token, token_type="access", settings=S)
    except TokenException:
        return
    assert isinstance(payload, Payload)


@given(
    alg=st.sampled_from(["HS256", "HS384", "HS512"]),
    other=st.sampled_from(["HS256", "HS384", "HS512", "none", "RS256", "hs256"]),
)
def test_header_alg_must_equal_configured_algorithm(alg, other):
    s = make_settings(alg)
    claims = valid_claims(now=int(time.time()))
    signing = alg if other not in ("HS256", "HS384", "HS512") else other
    token = forge({"typ": "JWT", "alg": other}, claims, sign_alg=signing)
    ok = verify_token(token, token_type="access", settings=s)
    assert ok == (other == alg)


distinct_secrets = st.lists(
    st.sampled_from(string.ascii_letters + string.digits),
    min_size=40,
    max_size=62,
    unique=True,
).map("".join)


@given(secret=distinct_secrets)
def test_tokens_only_verify_under_the_secret_that_signed_them(secret):
    assume(secret != SECRET)
    signer = make_settings(secret=secret)
    token, _ = issue_refresh_token("alice", settings=signer)
    assert verify_token(token, token_type="refresh", settings=signer) is True
    assert verify_token(token, token_type="refresh", settings=S) is False
