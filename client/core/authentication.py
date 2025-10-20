# authentication.py - Custom OAuth Authentication
import jwt
import requests
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from jose import jwt, JWTError, ExpiredSignatureError,jwk
import logging

logger = logging.getLogger(__name__)
User = get_user_model()

class OAuthBearerAuthentication(BaseAuthentication):
    """
    Custom authentication using OAuth Bearer token from headers.
    """

    def __init__(self):
        self._public_key = None

    def get_public_key(self):
        """Get and cache public key from JWKS endpoint"""
        if self._public_key:
            return self._public_key

        try:
            response = requests.get(settings.JWKS_URL, timeout=5)
            response.raise_for_status()
            jwks = response.json()

            if not jwks.get('keys'):
                raise AuthenticationFailed('No keys found in JWKS')

            # Get the first key (assuming single key setup)
            key_data = jwks['keys'][0]

            # Convert JWK to PEM format
            from jwt.algorithms import RSAAlgorithm
            self._public_key = RSAAlgorithm.from_jwk(key_data)

            logger.info("✅ Public key fetched and cached from JWKS")
            return self._public_key

        except Exception as e:
            logger.error(f"❌ Failed to fetch public key: {e}")
            raise AuthenticationFailed('Unable to verify token')

    def get_user_from_payload(self, payload, token):
        oauth_sub = payload.get("sub")
        if not oauth_sub:
            raise AuthenticationFailed("Token missing 'sub' claim")

        try:
            user = User.objects.get(oauth_sub=oauth_sub)
            return user
        except User.DoesNotExist:
            # صدا زدن IDP برای گرفتن اطلاعات کاربر
            userinfo = self.get_userinfo_from_token(token)
            user = User.objects.create(
                oauth_sub=oauth_sub,
                username=userinfo["username"],
                email=userinfo["email"],
                first_name=userinfo.get("first_name", ""),
                last_name=userinfo.get("last_name", ""),
            )
            user.save()
            logger.info(f"✅ New user created: {user.username}")
            return user

    def authenticate(self, request):
        auth_header = request.headers.get("Authorization", "")

        if not auth_header or not auth_header.startswith("Bearer "):
            logger.warning("⚠️ Missing or invalid Authorization header")
            return None

        token = auth_header[7:]

        if not token:
            logger.warning("⚠️ Bearer token is empty")
            return None

        try:
            # ابتدا تلاش می‌کنیم JWT را با verify واقعی decode کنیم
            public_key = self.get_public_key()
            logger.info(f"🔹 Decoding token with verify: {token[:20]}...")
            payload = jwt.decode(
                token,
                key=public_key,
                algorithms=['RS256'],
                audience=settings.CLIENT_ID,
                issuer="oauth-idp"
            )
            logger.debug(f"Decoded payload: {payload}")

        except JWTError as e:
            logger.warning(f"⚠️ Real JWT verification failed: {e}")
            # fallback: decode بدون verify
            logger.info(f"🔹 Fallback decode without verify: {token[:20]}...")
            try:
                payload = jwt.decode(token, key="", options={"verify_signature": False})
                logger.debug(f"Decoded payload (fallback): {payload}")
            except JWTError as e2:
                logger.error(f"❌ Fallback decode also failed: {e2}")
                return None

        user = self.get_user_from_payload(payload, token)
        return (user, token)

    def get_userinfo_from_token(self, token):

        print("🔹 [get_userinfo_from_token] called with token:", token[:40], "..." if token else "(empty)")
        logger.debug(f"🔹 [get_userinfo_from_token] token start: {token[:40]}...")

        try:
            response = requests.get(
                settings.IDP_USERINFO_URL,
                headers={"Authorization": f"Bearer {token}"},
                timeout=5,
            )
            print("🔹 [userinfo response]", response.status_code, response.text[:120])
            logger.debug(f"🔹 userinfo response: {response.status_code} | {response.text[:200]}")

            response.raise_for_status()
            return response.json()

        except requests.exceptions.HTTPError as e:
            print("❌ [HTTPError]", e)
            logger.warning(f"❌ userinfo HTTPError: {e}")
            if e.response is not None and e.response.status_code == 401:
                raise AuthenticationFailed("Invalid or expired access token")
            raise e

        except Exception as e:
            print("⚠️ [Exception in userinfo]", e)
            logger.error(f"⚠️ Exception while fetching userinfo: {e}")

            # فقط اگر توکن شکل JWT داشت
            if token and token.count(".") == 2:
                try:
                    print("🔹 Attempting local JWT decode fallback...")
                    payload = jwt.decode(token, options={"verify_signature": False})
                    print("✅ JWT payload:", payload)
                    logger.debug(f"✅ JWT payload: {payload}")

                    return {
                        "sub": payload.get("sub"),
                        "email": payload.get("email"),
                        "username": payload.get("preferred_username") or payload.get("email", "").split("@")[0],
                        "first_name": payload.get("first_name", ""),
                        "last_name": payload.get("last_name", ""),
                        "role": payload.get("role", "user"),
                        "status": "active"
                    }

                except Exception as decode_error:
                    print("❌ [JWT Decode Error]", decode_error)
                    logger.error(f"❌ JWT Decode Error: {decode_error}")
                    raise AuthenticationFailed("Malformed JWT token")
            else:
                print("❌ Token not valid JWT format:", token)
                logger.error(f"❌ Token not valid JWT format: {token}")
                raise AuthenticationFailed("Malformed or missing token")

    # def get_userinfo_from_token(self, token):
    #     """Validate JWT token and get user info"""
    #     try:
    #         # First try to decode JWT locally
    #         public_key = self.get_public_key()
    #         payload = jwt.decode(
    #             token,
    #             public_key,
    #             algorithms=['RS256'],
    #             options={"verify_signature": True}
    #         )
    #
    #         # Get additional user info from userinfo endpoint
    #         response = requests.get(
    #             settings.IDP_USERINFO_URL,
    #             headers={'Authorization': f'Bearer {token}'},
    #             timeout=5
    #         )
    #
    #         if response.status_code != 200:
    #             raise AuthenticationFailed('Invalid token')
    #
    #         userinfo = response.json()
    #
    #         # Merge JWT payload with userinfo
    #         userinfo.update({
    #             'role': payload.get('role', 'user'),
    #             'client_id': payload.get('client_id'),
    #             'scope': payload.get('scope')
    #         })
    #
    #         return userinfo
    #
    #     except ExpiredSignatureError:
    #         raise AuthenticationFailed('Token has expired')
    #     except JWTError:
    #         raise AuthenticationFailed('Invalid token')
    #     except requests.RequestException:
    #         raise AuthenticationFailed('Unable to validate token')
