"""
Module: easy_jwt.exceptions
"""


class JWTException(Exception): ...


class InvalidSettings(JWTException): ...


class TokenException(JWTException): ...


class InvalidPayload(TokenException): ...


class ExpiredToken(TokenException): ...
