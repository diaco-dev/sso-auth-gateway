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
    Custom authentication that validates OAuth Bearer tokens
    and creates/updates local User objects
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

            # فرض: فعلاً فقط یک کلید داریم
            key_data = jwks['keys'][0]

            # ساختن public key از JWK
            key = jwk.construct(key_data, algorithm='RS256')
            self._public_key = key

            return self._public_key

        except Exception as e:
            logger.error(f"Failed to fetch public key: {e}")
            raise AuthenticationFailed('Unable to verify token')

    def authenticate(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION')

        if not auth_header or not auth_header.startswith('Bearer '):
            return None

        token = auth_header.split(' ')[1]

        try:
            # Validate token and get user info
            userinfo = self.validate_token_and_get_userinfo(token)

            # Get or create local user
            user = self.get_or_create_user(userinfo)

            return (user, token)

        except AuthenticationFailed:
            raise
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            raise AuthenticationFailed('Token validation failed')

    def validate_token_and_get_userinfo(self, token):
        """Validate JWT token and get user info"""
        try:
            public_key = self.get_public_key()
            payload = jwt.decode(
                token,
                public_key,
                algorithms=['RS256'],
                options={"verify_signature": True},
                audience=settings.CLIENT_ID,  # enforce aud
                issuer="oauth-idp"            # enforce iss
            )

            # Base userinfo from JWT itself
            userinfo = {
                'sub': payload['sub'],
                'client_id': payload.get('client_id'),
                'scope': payload.get('scope'),
                'role': payload.get('role', 'user'),
            }

            # Optional: enrich userinfo from IDP endpoint
            try:
                response = requests.get(
                    settings.IDP_USERINFO_URL,
                    headers={'Authorization': f'Bearer {token}'},
                    timeout=5
                )
                if response.status_code == 200:
                    userinfo.update(response.json())
            except requests.RequestException:
                logger.warning("Failed to fetch userinfo endpoint, using JWT only")

            return userinfo


        except ExpiredSignatureError:

            raise AuthenticationFailed('Token has expired')

        except JWTError:

            raise AuthenticationFailed('Invalid token')

    def get_or_create_user(self, userinfo):
        """Get or create local user from OAuth userinfo"""
        oauth_sub = userinfo['sub']

        try:
            user = User.objects.get(oauth_sub=oauth_sub)

            # Update fields if needed
            updated = False
            if user.email != userinfo.get('email', ''):
                user.email = userinfo.get('email', '')
                updated = True
            if user.mobile != userinfo.get('mobile', ''):
                user.mobile = userinfo.get('mobile', '')
                updated = True
            if user.first_name != userinfo.get('first_name', ''):
                user.first_name = userinfo.get('first_name', '')
                updated = True
            if user.last_name != userinfo.get('last_name', ''):
                user.last_name = userinfo.get('last_name', '')
                updated = True
            if user.role != userinfo.get('role', 'user'):
                user.role = userinfo.get('role', 'user')
                updated = True

            if updated:
                user.save()

            return user

        except User.DoesNotExist:
            username = userinfo.get('username') or f"user_{oauth_sub}"

            # Ensure unique username
            counter = 1
            original_username = username
            while User.objects.filter(username=username).exists():
                username = f"{original_username}_{counter}"
                counter += 1

            user = User.objects.create(
                username=username,
                email=userinfo.get('email', ''),
                mobile=userinfo.get('mobile', ''),
                first_name=userinfo.get('first_name', ''),
                last_name=userinfo.get('last_name', ''),
                role=userinfo.get('role', 'user'),
                oauth_sub=oauth_sub,
                is_oauth_user=True,
                is_active=userinfo.get('status') == 'active'
            )

            logger.info(f"Created new OAuth user: {user.username}")
            return user