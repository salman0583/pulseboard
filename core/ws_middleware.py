import jwt
from django.conf import settings


def get_cookie(headers, name):
    for header in headers:
        if header[0] == b"cookie":
            cookies = header[1].decode().split(";")
            for c in cookies:
                if name in c:
                    return c.split("=")[1].strip()
    return None


class JWTWebSocketAuthMiddleware:
    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):

        token = get_cookie(scope["headers"], "access_token")

        if not token:
            print("[WS AUTH] No cookie token")
            scope["user_email"] = None
            return await self.inner(scope, receive, send)

        try:
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=["HS256"],
            )
            scope["user_email"] = payload.get("sub")

            print("[WS AUTH] OK", scope["user_email"])

        except Exception as e:
            print("[WS AUTH] Invalid:", str(e))
            scope["user_email"] = None

        return await self.inner(scope, receive, send)
