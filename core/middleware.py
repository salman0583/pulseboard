# core/middleware.py
import logging
from django.http import JsonResponse
from django.conf import settings
from jwt import ExpiredSignatureError, InvalidTokenError

from jwt_utils import (
    decode_token,
    create_access_token,
    create_refresh_token,
    create_id_token,
)
from db import is_refresh_revoked, save_refresh_token, run_query

logger = logging.getLogger("django")

DEV_MODE = getattr(settings, "DEBUG", True)

COOKIE_KWARGS = {
    "httponly": True,
    "secure": False if DEV_MODE else True,
    "samesite": "Lax" if DEV_MODE else "None",
    "path": "/",
}


class AutoRefreshTokenMiddleware:
    """
    - For non-public paths:
        * Try access_token from cookie / header.
        * If valid → set request.user_username and continue.
        * If expired → try refresh_token.
            - If refresh valid and NOT revoked/expired:
                · issue new access+refresh (+id)
                · save new refresh in DB
                · set cookies
                · continue request
            - If missing/invalid/expired/revoked → clear cookies, 401.

    NOTE: We DO NOT revoke the refresh token here to avoid race conditions.
          Revocation is done only on explicit logout.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.public_prefixes = (
            "/api/register/",
            "/api/request-otp/",
            "/api/verify-otp/",
            "/api/login/",
            "/api/logout/",
            "/api/refresh/",
            "/admin/",
            "/static/",
        )

    def __call__(self, request):
        path = request.path

        # Skip public routes
        if path.startswith(self.public_prefixes):
            return self.get_response(request)

        # Read access token
        access_token = request.COOKIES.get("access_token")
        if not access_token:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                access_token = auth_header.split(" ")[1]

        if not access_token:
            # Anonymous route or no cookie — just let views decide.
            return self.get_response(request)

        # 1) Try normal access token
        try:
            payload = decode_token(access_token)
            username = payload.get("sub")
            request.user_username = username
            return self.get_response(request)

        except ExpiredSignatureError:
            # Need to go through refresh flow
            logger.info("Access token expired, attempting refresh")

            refresh_token = request.COOKIES.get("refresh_token")
            if not refresh_token:
                return self._clear_session(
                    JsonResponse(
                        {
                            "status": "error",
                            "message": "Session expired. Please log in again.",
                        },
                        status=401,
                    )
                )

            try:
                r_payload = decode_token(refresh_token)
                jti = r_payload["jti"]
                username = r_payload["sub"]

                # If user logged out or token expired in DB → block
                if is_refresh_revoked(jti):
                    logger.warning("[%s] Refresh token revoked / expired / unknown", username)
                    return self._clear_session(
                        JsonResponse(
                            {"status": "error", "message": "Refresh token invalid"},
                            status=401,
                        )
                    )

                # ✅ DO NOT revoke here → avoid race when many requests refresh at once

                # Issue new tokens
                new_access = create_access_token(username)
                new_refresh, new_jti, _ = create_refresh_token(username)

                # Save new refresh row
                new_r_payload = decode_token(new_refresh)
                save_refresh_token(new_jti, username, new_r_payload["exp"])

                # Optional: id_token (for front-end metadata)
                user_row = run_query(
                    "SELECT email, full_name FROM users WHERE username=%s",
                    (username,),
                    fetchone=True,
                ) or {"email": None, "full_name": None}

                new_id = create_id_token(
                    username,
                    user_row.get("email"),
                    user_row.get("full_name"),
                )

                request.user_username = username
                response = self.get_response(request)

                # Set cookies with new tokens
                response.set_cookie(
                    "access_token", new_access, max_age=600, **COOKIE_KWARGS
                )
                response.set_cookie(
                    "refresh_token",
                    new_refresh,
                    max_age=7 * 24 * 3600,
                    **COOKIE_KWARGS,
                )
                response.set_cookie("id_token", new_id, max_age=600, **COOKIE_KWARGS)

                logger.info("Rotated tokens for %s", username)
                return response

            except ExpiredSignatureError:
                logger.info("Refresh token expired")
                return self._clear_session(
                    JsonResponse(
                        {
                            "status": "error",
                            "message": "Session expired. Please log in again.",
                        },
                        status=401,
                    )
                )
            except InvalidTokenError:
                logger.info("Invalid refresh token")
                return self._clear_session(
                    JsonResponse(
                        {"status": "error", "message": "Invalid refresh token"},
                        status=401,
                    )
                )
            except Exception as e:
                logger.exception("Auto refresh failed: %s", e)
                return self._clear_session(
                    JsonResponse(
                        {"status": "error", "message": "Auto refresh failed"},
                        status=401,
                    )
                )

        except InvalidTokenError:
            logger.info("Invalid access token")
            return self._clear_session(
                JsonResponse(
                    {"status": "error", "message": "Invalid access token"},
                    status=401,
                )
            )
        except Exception as e:
            logger.exception("Token error: %s", e)
            return self._clear_session(
                JsonResponse(
                    {"status": "error", "message": "Unauthorized"}, status=401
                )
            )

    def _clear_session(self, response):
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")
        response.delete_cookie("id_token")
        return response
