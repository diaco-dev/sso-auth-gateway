import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-pz!7ymb__di*sw#7_lk&zrrxjwj7^jgxj%&fli4=eax8%nxv*q'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ["localhost", "127.0.0.1"]


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework_simplejwt',
    'rest_framework.authtoken',
    'rest_framework_simplejwt.token_blacklist',
    "django_extensions",
    'corsheaders',
    'core',
    'task',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates']
        ,
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.2/ref/settings/#databases

# Database configuration
DATABASES = {
    'default': {
        "ENGINE": "django.db.backends.postgresql",
        'NAME': os.getenv("POSTGRES_DB"),
        'USER': os.getenv("POSTGRES_USER"),
        'PASSWORD': os.getenv("POSTGRES_PASSWORD"),
        'HOST': os.getenv("POSTGRES_HOST"),
        'PORT': os.getenv("POSTGRES_PORT"),
    }
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.core.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.core.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.core.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.core.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.2/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/5.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# OIDC / OAuth2 settings
CLIENT_ID = os.getenv("CLIENT_ID", "your-client-id")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "your-client-secret")

IDP_AUTHORIZE_URL = os.getenv("IDP_AUTHORIZE_URL", "http://localhost:8000/o/authorize/")
IDP_TOKEN_URL = os.getenv("IDP_TOKEN_URL", "http://localhost:8000/o/token/")
IDP_USERINFO_URL = os.getenv("IDP_USERINFO_URL", "http://localhost:8000/o/userinfo/")

REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:8001/callback/")
JWKS_URL = os.getenv("OAUTH_JWKS_URL", "http://localhost:8000/.well-known/jwks.json")

#----production
ENVIRONMENT = os.getenv("ENVIRONMENT")
# Allowed hosts
if ENVIRONMENT == "production":
    print(ENVIRONMENT)
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    debug = False
    ALLOWED_HOSTS = os.getenv("DJANGO_ALLOWED_HOSTS", "").split(",")
    ALLOWED_EXPORT_IPS = os.environ.get("ALLOWED_EXPORT_HOSTS", default='').split(",")
    CSRF_TRUSTED_ORIGINS = os.environ.get("CSRF_TRUSTED_ORIGINS", default='').split(",")
    ALLOWED_USER = os.environ.get("ALLOWED_USER", default='')
    SECRET_KEY_API = os.getenv("SECRET_KEY_API",default='')
    CORS_ALLOW_ALL_ORIGINS = False
    CORS_ALLOWED_ORIGINS = [
        "https://api.ceoassist.ai",
        "https://www.api.ceoassist.ai",
        "http://core.ceoassist.ai",
        "https://core.ceoassist.ai",
        "http://proxy.ceoassist.ai",
        "https://proxy.ceoassist.ai",
        "http://116.203.68.109",
        "https://116.203.68.109",
        "https://188.75.113.129",
        "http://188.75.113.129",
    ]


else:  # development
    print(ENVIRONMENT)
    CORS_ALLOW_CREDENTIALS = True
    SESSION_COOKIE_SECURE = False
    CSRF_COOKIE_SECURE = False
    ALLOWED_EXPORT_IPS = os.environ.get("ALLOWED_EXPORT_HOSTS", default='').split(",")
    ALLOWED_HOSTS = os.getenv("DJANGO_ALLOWED_HOSTS", "").split(",")
    ALLOWED_USER = os.environ.get("ALLOWED_USER", default='')
    SECRET_KEY_API = os.getenv("SECRET_KEY_API", "fallback-secret-key")
    CORS_ALLOW_ALL_ORIGINS = False  # Explicitly disable
    CORS_ALLOWED_ORIGINS = [
        "http://localhost:8000",  # FastAPI server
        "http://127.0.0.1:8000",
        "http://localhost:8001",  # Django client
        "http://127.0.0.1:8001",
    ]
    CSRF_TRUSTED_ORIGINS = [
        "http://localhost",
        "http://localhost:8000",
        "http://127.0.0.1",
        "http://127.0.0.1:8000"
    ]

SESSION_ENGINE = "django.contrib.sessions.backends.db"

AUTH_USER_MODEL = 'core.User'


# Django REST Framework Configuration
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'core.authentication.OAuthBearerAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'core.permissions.IsOAuthAuthenticated',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ],
}

#SWAGGER
SPECTACULAR_SETTINGS = {
    'TITLE': 'FioTriX API Documentation',
    'DESCRIPTION': 'API documentation for fiotrix-services_app',
    'VERSION': '1.0.0',

    'SERVE_INCLUDE_SCHEMA': True,
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
    'COMPONENT_SPLIT_REQUEST': True,

    'SWAGGER_UI_SETTINGS': {
        'deepLinking': True,
        'persistAuthorization': True,
    },

    'SECURITY': [{'BearerAuth': []}],
    'COMPONENTS': {
        'securitySchemes': {
            'BearerAuth': {
                'type': 'http',
                'scheme': 'bearer',
                'bearerFormat': 'JWT',
            }
        }
    },

    'ENUM_NAME_OVERRIDES': {},
    'TAG_SORTING': 'alpha',
}
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        '__name__': {
            'handlers': ['console'],
            'level': 'INFO',
        },
    },
}