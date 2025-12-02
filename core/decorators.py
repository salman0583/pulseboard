# core/decorators.py
from functools import wraps
from django.http import JsonResponse
from jwt import ExpiredSignatureError, InvalidTokenError

from jwt_utils import decode_token


def require_access_token(view_func):
    """
    Simple auth decorator:
      - Uses request.user_username if middleware already set it.
      - Otherwise decodes access_token cookie (or Bearer header).
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
