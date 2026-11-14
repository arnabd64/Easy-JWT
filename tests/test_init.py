import easy_jwt


def test_public_api():
    assert set(easy_jwt.__all__) == {
        "JWTSettings",
        "issue_access_token",
        "issue_refresh_token",
        "parse_token",
        "renew_access_token",
        "verify_token",
    }
    for name in easy_jwt.__all__:
        assert hasattr(easy_jwt, name)


def test_exports_are_the_core_objects():
    from easy_jwt import core, settings

    assert easy_jwt.parse_token is core.parse_token
    assert easy_jwt.JWTSettings is settings.JWTSettings
