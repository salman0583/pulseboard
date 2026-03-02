"""
Django settings for learning project.
"""

from pathlib import Path
import os
import configparser
import datetime

# ======================================================
# BASE
# ======================================================

BASE_DIR = Path(__file__).resolve().parent.parent

config = configparser.ConfigParser()
config.read(os.path.join(BASE_DIR, "config.ini"))

# ======================================================
# SECURITY
# ======================================================

SECRET_KEY = "django-insecure-ei957s6(@x-h4mo+0*21w$$i^%+vp6&337o1xsvh$^+13c13^y"


DEBUG = True

ALLOWED_HOSTS = [
    "127.0.0.1",
    "localhost",
    "crocodiloid-na-ungovernmental.ngrok-free.dev",
    "192.168.0.36",
    "*",
]

OTP_TEST_MODE = True  # 🔁 False in production
OTP_MASTER_CODE = "000000"  # used only when test mode = True
OTP_EXPIRY_MINUTES = 5

import configparser
import os

config = configparser.ConfigParser()
config.read(os.path.join(BASE_DIR, "config.ini"))



# ======================================================
# JWT CONFIG
# ======================================================

JWT_SECRET = SECRET_KEY
JWT_ALG = "HS256"

JWT_ACCESS_TTL = datetime.timedelta(minutes=10)
JWT_REFRESH_TTL = datetime.timedelta(days=7)
JWT_OTP_TTL = datetime.timedelta(minutes=5)

JWT_ACCESS_COOKIE_NAME = "access_token"
JWT_REFRESH_COOKIE_NAME = "refresh_token"

# ======================================================
# COOKIE CONFIG (🔥 VERY IMPORTANT)
# ======================================================

COOKIE_KWARGS = {
    "httponly": True,
    "secure": False,  # ❗ MUST be False on localhost
    "samesite": "Lax",  # ❗ Lax works for same-site dev
}

CSRF_COOKIE_SECURE = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SAMESITE = "Lax"

# ======================================================
# APPLICATIONS
# ======================================================

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Third-party
    "corsheaders",
    "channels",
    # Local
    "core",
]

# ======================================================
# MIDDLEWARE (ORDER MATTERS)
# ======================================================

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    # ✅ Your refresh-token middleware
    "core.middleware.AutoRefreshTokenMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

# ======================================================
# CORS (🔥 CORRECT & SAFE)
# ======================================================

CORS_ALLOW_CREDENTIALS = True

# ======================================================
# CORS (ALLOW FRONTEND)
# ======================================================

CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_CREDENTIALS = True

CORS_ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://192.168.0.36:5173",
]

CSRF_TRUSTED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://192.168.0.36:5173",
]


# ❌ DO NOT USE CORS_ALLOW_ALL_ORIGINS WITH CREDENTIALS

# ======================================================
# URL / TEMPLATES
# ======================================================

ROOT_URLCONF = "learning.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# ======================================================
# ASGI / CHANNELS
# ======================================================

ASGI_APPLICATION = "learning.asgi.application"

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [("192.168.0.120", 6379)],
        },
    },
}

# ======================================================
# DATABASE
# ======================================================

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": config["mysql"]["NAME"],
        "USER": config["mysql"]["USER"],
        "PASSWORD": config["mysql"]["PASSWORD"],
        "HOST": config["mysql"]["HOST"],
        "PORT": config["mysql"]["PORT"],
    }
}

# ======================================================
# EMAIL (OTP)
# ======================================================

EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = "syedsalman0583@gmail.com"
EMAIL_HOST_PASSWORD = "unznboywfkdhitip"

# ======================================================
# LOGGING
# ======================================================

LOGS_DIR = BASE_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
        },
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": LOGS_DIR / "app.log",
            "maxBytes": 1024 * 1024 * 10,
            "backupCount": 5,
        },
    },
    "root": {
        "handlers": ["console", "file"],
        "level": "INFO",
    },
}

# ======================================================
# STATIC / I18N
# ======================================================

STATIC_URL = "/static/"

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


