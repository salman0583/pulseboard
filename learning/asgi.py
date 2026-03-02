import os

from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter

from core.routing import websocket_urlpatterns
from core.ws_middleware import JWTWebSocketAuthMiddleware


# 🔥 THIS LINE WAS MISSING / WRONG
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "learning.settings")


django_asgi_app = get_asgi_application()

application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": JWTWebSocketAuthMiddleware(
        URLRouter(websocket_urlpatterns)
    ),
})
