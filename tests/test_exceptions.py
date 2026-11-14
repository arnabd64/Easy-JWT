import pytest

from easy_jwt.exceptions import (
    ExpiredToken,
    InvalidPayload,
    InvalidSettings,
    JWTException,
    TokenException,
)


@pytest.mark.parametrize(
    ("exc", "parent"),
    [
        (JWTException, Exception),
        (InvalidSettings, JWTException),
        (TokenException, JWTException),
        (InvalidPayload, TokenException),
        (ExpiredToken, TokenException),
    ],
)
def test_hierarchy(exc, parent):
    assert issubclass(exc, parent)


def test_settings_errors_are_not_token_errors():
    # verify_token relies on this: misconfiguration must not look like a bad token
    assert not issubclass(InvalidSettings, TokenException)


def test_sibling_token_errors_are_distinct():
    assert not issubclass(ExpiredToken, InvalidPayload)
    assert not issubclass(InvalidPayload, ExpiredToken)


@pytest.mark.parametrize(
    "exc", [JWTException, InvalidSettings, TokenException, InvalidPayload, ExpiredToken]
)
def test_message_is_preserved(exc):
    with pytest.raises(exc, match="boom"):
        raise exc("boom")
