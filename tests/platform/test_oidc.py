import time
from types import SimpleNamespace

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("authlib")

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

from silentsec.platform.auth import oidc
from silentsec.platform.config import Settings


@pytest.fixture
def signing(monkeypatch):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client = SimpleNamespace(
        get_signing_key_from_jwt=lambda _: SimpleNamespace(key=private.public_key())
    )
    monkeypatch.setattr(oidc, "jwks_client", lambda _: client)
    settings = Settings(
        environment="test",
        session_secret="s" * 64,
        auth_mode="oidc",
        dev_login_code="",
        oidc_issuer="https://id.example.test",
        oidc_client_id="web-client",
        oidc_client_secret="test-secret",
        oidc_audience="silentsec-api",
        oidc_jwks_url="https://id.example.test/jwks",
    )
    claims = {
        "sub": "user-1",
        "iss": settings.oidc_issuer,
        "aud": settings.oidc_audience,
        "iat": int(time.time()),
        "exp": int(time.time()) + 300,
    }
    return settings, private, claims


@pytest.mark.parametrize(
    "change", [{"iss": "https://evil.test"}, {"aud": "other"}, {"exp": 1}, {"sub": ""}]
)
def test_oidc_claim_rejections(signing, change):
    settings, key, claims = signing
    token = jwt.encode({**claims, **change}, key, algorithm="RS256")
    with pytest.raises(HTTPException) as failure:
        oidc.verify_token(settings, token, audience=settings.oidc_audience)
    assert failure.value.status_code == 401


def test_valid_oidc_and_mfa_fail_closed(signing):
    settings, key, claims = signing
    token = jwt.encode(claims, key, algorithm="RS256")
    assert oidc.verify_token(settings, token, audience=settings.oidc_audience)["sub"] == "user-1"
    assert not oidc.mfa_verified(settings, claims)
    assert oidc.mfa_verified(settings, {**claims, "amr": ["pwd", "mfa"]})


def test_unsigned_and_wrong_signature_rejected(signing):
    settings, _, claims = signing
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    for token in [
        jwt.encode(claims, other, algorithm="RS256"),
        jwt.encode(claims, "", algorithm="none"),
    ]:
        with pytest.raises(HTTPException):
            oidc.verify_token(settings, token, audience=settings.oidc_audience)


def test_production_state_cookie_is_host_bound_and_deletion_stays_secure(signing):
    from fastapi import Response

    from silentsec.platform.auth.routes import clear_cookie

    settings, _, _ = signing
    # This unit test isolates cookie formatting from deployment validation;
    # the actual production startup guard still requires PostgreSQL and OIDC.
    cookie_profile = settings.model_copy(update={"environment": "production"})
    assert cookie_profile.cookie_name.startswith("__Host-")
    assert cookie_profile.oidc_cookie_name.startswith("__Host-")
    for name in (cookie_profile.cookie_name, cookie_profile.oidc_cookie_name):
        response = Response()
        clear_cookie(response, cookie_profile, name)
        header = response.headers["set-cookie"]
        assert "Secure" in header and "HttpOnly" in header and "Path=/" in header
        assert "Domain=" not in header
