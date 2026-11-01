"""OIDC code+PKCE client and strict JWT verifier. No password grant."""

import secrets
from functools import lru_cache

import jwt
from authlib.integrations.httpx_client import AsyncOAuth2Client
from fastapi import HTTPException


@lru_cache(maxsize=8)
def jwks_client(url):
    return jwt.PyJWKClient(url, cache_jwk_set=True, lifespan=300, timeout=5)


def verify_token(settings, token, audience):
    if len(token) > 16384:
        raise HTTPException(401, "Identity token exceeds the size limit.")
    try:
        key = jwks_client(settings.oidc_jwks_url).get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            key.key,
            algorithms=["RS256", "ES256"],
            audience=audience,
            issuer=settings.oidc_issuer,
            options={"require": ["iss", "aud", "sub", "exp", "iat"]},
            leeway=10,
        )
        if not isinstance(claims["sub"], str) or not claims["sub"]:
            raise ValueError("Invalid subject")
        if (
            isinstance(claims["aud"], list)
            and len(claims["aud"]) > 1
            and claims.get("azp") != settings.oidc_client_id
        ):
            raise ValueError("Invalid authorized party")
        return claims
    except (jwt.PyJWTError, ValueError, KeyError, OSError) as exc:
        raise HTTPException(401, "Identity token verification failed.") from exc


def client(settings, verifier=None):
    return AsyncOAuth2Client(
        settings.oidc_client_id,
        settings.oidc_client_secret.get_secret_value(),
        redirect_uri=settings.origin + "/api/v1/auth/callback",
        scope="openid email profile",
        code_challenge_method="S256",
        timeout=10,
    )


async def metadata(settings):
    import httpx

    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as http:
            response = await http.get(
                settings.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration"
            )
            response.raise_for_status()
            document = response.json()
        from urllib.parse import urlsplit

        if document.get("issuer") != settings.oidc_issuer:
            raise ValueError("Issuer mismatch")
        for name in ("authorization_endpoint", "token_endpoint"):
            value = urlsplit(document[name])
            if value.scheme != "https" or value.username:
                raise ValueError("Invalid provider endpoint")
        return document
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        raise HTTPException(503, "Identity provider unavailable.") from exc


def mfa_verified(settings, claims):
    methods = claims.get("amr", [])
    return (isinstance(methods, list) and "mfa" in methods) or claims.get(
        "acr"
    ) in settings.oidc_mfa_acr


def new_attempt():
    return secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(48)
