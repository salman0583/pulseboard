# core/decorators.py
from functools import wraps
from django.http import JsonResponse
from jwt import ExpiredSignatureError, InvalidTokenError
from db import run_query
from jwt_utils import decode_token,is_refresh_token_revoked


def require_access_token(view_func):
    """
    Auth decorator:
    - Extracts user_email from JWT
    - Resolves admin flag once
    - Makes identity consistent across views
    """

    @wraps(view_func)
    def wrapper(request, *args, **kwargs):

        # Try cookie or bearer token
        token = request.COOKIES.get("access_token")

        if not token:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

        if not token:
            return JsonResponse(
                {"status": "error", "message": "Authentication required"},
                status=401,
            )

        try:
            payload = decode_token(token)

            # ✅ SINGLE SOURCE OF IDENTITY
            user_email = payload.get("sub")
            if not user_email:
                return JsonResponse(
                    {"status": "error", "message": "Invalid token payload"},
                    status=401,
                )

            request.user_email = user_email

            # ✅ RESOLVE ADMIN FLAG HERE (CRITICAL)
            row = run_query(
                """
                SELECT is_admin
                FROM users
                WHERE email = %s AND is_active = 1
                """,
                (user_email,),
                fetchone=True,
            )

            request.is_admin = bool(row and row["is_admin"])

        except ExpiredSignatureError:
            return JsonResponse(
                {"status": "error", "message": "Session expired"},
                status=401,
            )
        except InvalidTokenError:
            return JsonResponse(
                {"status": "error", "message": "Invalid access token"},
                status=401,
            )

        return view_func(request, *args, **kwargs)

    return wrapper


# def require_access_token(view_func):
    """
    Simple auth decorator:
      - Uses request.user_username if middleware already set it.
      - Otherwise decodes access_token cookie (or Bearer header).
      - Also checks that the session jti is not revoked.
    """

    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        # If middleware already set user, trust it
        user = getattr(request, "user_username", None)
        if user:
            return view_func(request, *args, **kwargs)

        # Otherwise read cookie / header
        token = request.COOKIES.get("access_token")
        if not token:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

        if not token:
            return JsonResponse(
                {"status": "error", "message": "Authentication required"},
                status=401,
            )

        try:
            payload = decode_token(token)

            # Must be an access token
            if payload.get("typ") != "access":
                return JsonResponse(
                    {"status": "error", "message": "Access token required"},
                    status=401,
                )

            # Every new access token should have a jti
            jti = payload.get("jti")
            if not jti:
                # Old tokens without jti are considered invalid
                return JsonResponse(
                    {"status": "error", "message": "Session invalid"},
                    status=401,
                )

            # Check if this session has been revoked (logout)
            if is_refresh_token_revoked(jti):
                return JsonResponse(
                    {"status": "error", "message": "Session expired"},
                    status=401,
                )

            # OK: attach user to request and continue
            request.user_username = payload.get("sub")

        except ExpiredSignatureError:
            return JsonResponse(
                {"status": "error", "message": "Session expired"},
                status=401,
            )
        except InvalidTokenError:
            return JsonResponse(
                {"status": "error", "message": "Invalid access token"},
                status=401,
            )

        return view_func(request, *args, **kwargs)

    return wrapper