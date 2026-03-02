import asyncio
import json
import datetime
import logging
from urllib.parse import parse_qs
from http.cookies import SimpleCookie
from typing import Optional, Dict, Any

from channels.generic.websocket import AsyncWebsocketConsumer
from asgiref.sync import sync_to_async
from db import insert_and_get_id, run_query, is_refresh_revoked
from jwt_utils import (
    _resolve_to_email,
    _is_workspace_member,
    decode_token,
    _broadcast_activity,
    broadcast_notification,
    safe_group_name,
)

logger = logging.getLogger("django")

# ==========================================================
# 🔐 AUTH UTIL
# ==========================================================


def get_user_from_scope(scope: Dict[str, Any]) -> Optional[str]:
    """
    Extract token from WebSocket headers (cookie) or query string.
    Prefer access_token; fallback to refresh_token (if valid & not revoked).
    Returns user identifier string or None.
    """
    try:
        headers = scope.get("headers") or []

        # DEBUG: log raw headers for troubleshooting (remove when stable)
        try:
            headers_debug = [(k, v) for k, v in headers]
            logger.debug("[WSAuth] scope headers (raw): %s", headers_debug)
        except Exception:
            logger.debug("[WSAuth] cannot stringify headers debug")

        raw_cookie = None
        for name, val in headers:
            if name == b"cookie":
                try:
                    raw_cookie = val.decode()
                except Exception:
                    raw_cookie = val.decode("latin-1")
                break

        cookies: Dict[str, str] = {}
        if raw_cookie:
            for part in raw_cookie.split(";"):
                part = part.strip()
                if not part:
                    continue
                k, sep, v = part.partition("=")
                if not sep:
                    continue
                cookies[k] = v

        # try access token first
        access_token = (
            cookies.get("access_token") or cookies.get("access") or cookies.get("jwt")
        )

        # fallback to querystring token (dev/test only)
        if not access_token:
            qs_bytes = scope.get("query_string", b"")
            if qs_bytes:
                try:
                    qs = parse_qs(qs_bytes.decode())
                    tlist = (
                        qs.get("token") or qs.get("access") or qs.get("access_token")
                    )
                    if tlist:
                        access_token = tlist[0]
                        logger.debug(
                            "[WSAuth] using token from query string (fallback)"
                        )
                except Exception:
                    logger.debug("[WSAuth] failed to parse query string for token")

        # try decode access token
        if access_token:
            try:
                payload = decode_token(access_token)
                user = (
                    payload.get("sub") or payload.get("user_id") or payload.get("email")
                )
                if user:
                    logger.info(
                        "[WSAuth] Authenticated WebSocket user (access token): %s",
                        user,
                    )
                    return user
            except Exception as e:
                logger.debug("[WSAuth] access_token decode failed: %s", e)
                # continue to refresh fallback

        # ACCESS failed — try refresh fallback
        refresh_token = cookies.get("refresh_token")
        if not refresh_token:
            logger.warning("[WSAuth] No access token found in cookie or query string")
            return None

        # decode refresh token and check revocation
        try:
            rpayload = decode_token(refresh_token)
            jti = rpayload.get("jti")
            username = (
                rpayload.get("sub") or rpayload.get("user_id") or rpayload.get("email")
            )
            if not username:
                logger.warning("[WSAuth] refresh token missing user claim")
                return None

            # check revocation
            try:
                if is_refresh_revoked(jti):
                    logger.warning(
                        "[WSAuth] refresh token revoked (jti=%s) - denying WS",
                        jti,
                    )
                    return None
            except Exception as e:
                logger.exception("[WSAuth] failed to check refresh revocation: %s", e)
                return None

            logger.info(
                "[WSAuth] Authenticated WebSocket user (refresh token fallback): %s",
                username,
            )
            return username

        except Exception as e:
            logger.warning(
                "[WSAuth] refresh_token decode failed or expired: %s",
                e,
            )
            return None

    except Exception as e:
        logger.exception("[WSAuth] Unexpected error while extracting user: %s", e)
        return None


# ==========================================================
# 🧱 BASE CONSUMER WITH COMMON LOGIC
# ==========================================================


def _safe_dm_group_for_email(email: str) -> str:
    """
    Convert an email into a safe Channels group name.
    Example: 'khan@example.com' -> 'dmuser_khan_example_com'
    """
    safe = (email or "").replace("@", "_at_").replace(".", "_")
    return f"dmuser_{safe}"


class BaseAuthedConsumer(AsyncWebsocketConsumer):
    """
    Shared logic:
    - Authenticate user on connect
    - Unified send_json / error formats
    """

    async def connect(self) -> None:
        self.user: Optional[str] = get_user_from_scope(self.scope)
        if not self.user:
            logger.warning(
                "[%s] Connection denied: unauthenticated WebSocket",
                self.__class__.__name__,
            )
            await self.close(code=4403)  # forbidden
            return

        await self.accept()
        logger.info(
            "[%s] %s connected via WS",
            self.__class__.__name__,
            self.user,
        )

    async def send_json(self, data: Dict[str, Any]) -> None:
        await self.send(text_data=json.dumps(data))

    async def send_error(
        self,
        message: str,
        code: str = "error",
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        payload: Dict[str, Any] = {
            "event": "error",
            "code": code,
            "message": message,
        }
        if extra:
            payload.update(extra)
        await self.send_json(payload)

    async def receive(
        self,
        text_data: Optional[str] = None,
        bytes_data: Optional[bytes] = None,
    ) -> None:
        """
        Children should override handle_action(...).
        """
        try:
            data = json.loads(text_data or "{}")
        except Exception:
            await self.send_error("Invalid JSON payload", code="bad_json")
            return

        action = data.get("action")
        if not action:
            await self.send_error("Missing 'action' field", code="missing_action")
            return

        # safety check
        if not getattr(self, "user", None):
            await self.send_error("Unauthenticated WebSocket", code="unauthenticated")
            await self.close(code=4403)  # forbidden
            return

        try:
            await self.handle_action(action, data)
        except Exception as e:
            logger.exception(
                "[%s] receive error: %s",
                self.__class__.__name__,
                e,
            )
            # if message is empty, at least send the exception type
            msg = str(e) or e.__class__.__name__
            await self.send_error(msg)

    async def handle_action(
        self,
        action: str,
        data: Dict[str, Any],
    ) -> None:
        """
        To be implemented by subclasses.
        """
        raise NotImplementedError("handle_action must be implemented by subclass")


# ==========================================================
# 💬 CHAT CONSUMER
# ==========================================================


import datetime
from typing import Dict, Any
from channels.db import database_sync_to_async as sync_to_async


# class ChatConsumer(BaseAuthedConsumer):
#     """
#     WebSocket consumer for:
#     - Workspace channel chat
#     - Direct messages (DM)
#     """

#     # =====================================================
#     # HELPERS
#     # =====================================================

#     async def _get_sender_name(self, email: str) -> str:
#         row = await sync_to_async(run_query)(
#             "SELECT full_name FROM users WHERE email=%s",
#             (email,),
#             fetchone=True,
#         )
#         return row["full_name"] if row and row.get("full_name") else email

#     async def _ensure_dm_identity(self) -> None:
#         if hasattr(self, "user_email"):
#             return

#         email = await sync_to_async(_resolve_to_email)(self.user)
#         self.user_email = email or self.user
#         self.dm_group_name = _safe_dm_group_for_email(self.user_email)

#         await self.channel_layer.group_add(
#             self.dm_group_name,
#             self.channel_name,
#         )

#     # =====================================================
#     # ROUTER
#     # =====================================================

#     async def handle_action(self, action: str, data: Dict[str, Any]) -> None:
#         if action == "join":
#             await self._handle_join(data)
#         elif action == "send":
#             await self._handle_send(data)
#         elif action == "sync_history":
#             await self._handle_sync_history(data)

#         # ---------- DIRECT MESSAGES ----------
#         elif action == "dm_send":
#             await self._handle_dm_send(data)
#         elif action == "dm_history":
#             await self._handle_dm_history(data)
#         else:
#             await self.send_json(
#                 {
#                     "event": "error",
#                     "message": "Invalid action",
#                     "received": action,
#                 }
#             )

#     # =====================================================
#     # CHANNEL CHAT
#     # =====================================================

#     async def _handle_join(self, data: Dict[str, Any]) -> None:
#         try:
#             self.channel_id = int(data.get("channel_id"))
#         except (TypeError, ValueError):
#             await self.send_json(
#                 {
#                     "event": "error",
#                     "message": "Invalid channel_id",
#                 }
#             )
#             return

#         self.group_name = f"chat_{self.channel_id}"

#         await self.channel_layer.group_add(
#             self.group_name,
#             self.channel_name,
#         )

#     async def _handle_send(self, data: Dict[str, Any]) -> None:
#         if not hasattr(self, "channel_id"):
#             return

#         body = (data.get("body") or "").strip()
#         if not body:
#             return

#         sender_email = (
#             self.user_email
#             if hasattr(self, "user_email")
#             else await sync_to_async(_resolve_to_email)(self.user)
#         )

#         sender_name = await self._get_sender_name(sender_email)

#         msg_id = await sync_to_async(insert_and_get_id)(
#             """
#             INSERT INTO messages (channel_id, sender_email, body)
#             VALUES (%s, %s, %s)
#             """,
#             (self.channel_id, sender_email, body),
#         )

#         payload = {
#             "event": "message",
#             "id": msg_id,
#             "channel_id": self.channel_id,
#             "sender_email": sender_email,
#             "sender_name": sender_name,
#             "body": body,
#             "created_at": datetime.datetime.utcnow().isoformat() + "Z",
#         }

#         await self.channel_layer.group_send(
#             self.group_name,
#             {"type": "chat.message", "data": payload},
#         )

#     async def _handle_sync_history(self, data: Dict[str, Any]) -> None:
#         try:
#             channel_id = int(data.get("channel_id"))
#         except (TypeError, ValueError):
#             return

#         limit = min(int(data.get("limit", 50)), 100)

#         rows = await sync_to_async(run_query)(
#             """
#             SELECT
#                 m.id,
#                 m.sender_email,
#                 m.body,
#                 m.created_at,
#                 u.full_name
#             FROM messages m
#             LEFT JOIN users u ON u.email = m.sender_email
#             WHERE m.channel_id = %s
#             ORDER BY m.created_at ASC
#             LIMIT %s
#             """,
#             (channel_id, limit),
#             fetchall=True,
#         )

#         messages = [
#             {
#                 "id": r["id"],
#                 "sender_email": r["sender_email"],
#                 "sender_name": r["full_name"] or r["sender_email"],
#                 "body": r["body"],
#                 "created_at": r["created_at"].isoformat(),
#             }
#             for r in rows or []
#         ]

#         await self.send_json(
#             {
#                 "event": "history",
#                 "messages": messages,
#             }
#         )

#     # =====================================================
#     # DIRECT MESSAGES
#     # =====================================================

#     async def _handle_dm_send(self, data: Dict[str, Any]) -> None:
#         await self._ensure_dm_identity()

#         body = (data.get("body") or "").strip()
#         workspace_id = data.get("workspace_id")
#         other_user = data.get("other_user")

#         if not body or not workspace_id or not other_user:
#             return

#         sender_email = self.user_email
#         sender_name = await self._get_sender_name(sender_email)
#         recipient_email = await sync_to_async(_resolve_to_email)(other_user)

#         dm_id = await sync_to_async(insert_and_get_id)(
#             """
#             INSERT INTO dm_messages
#                 (workspace_id, sender_email, recipient_email, body)
#             VALUES (%s, %s, %s, %s)
#             """,
#             (workspace_id, sender_email, recipient_email, body),
#         )

#         payload = {
#             "event": "dm_message",
#             "id": dm_id,
#             "workspace_id": workspace_id,
#             "sender_email": sender_email,
#             "sender_name": sender_name,
#             "recipient": recipient_email,
#             "body": body,
#             "created_at": datetime.datetime.utcnow().isoformat() + "Z",
#         }

#         await self.channel_layer.group_send(
#             _safe_dm_group_for_email(sender_email),
#             {"type": "dm.message", "data": payload},
#         )

#         await self.channel_layer.group_send(
#             _safe_dm_group_for_email(recipient_email),
#             {"type": "dm.message", "data": payload},
#         )

#     async def _handle_dm_history(self, data: Dict[str, Any]) -> None:
#         await self._ensure_dm_identity()

#         workspace_id = data.get("workspace_id")
#         other_user = data.get("other_user")
#         limit = min(int(data.get("limit", 50)), 100)

#         if not workspace_id or not other_user:
#             return

#         other_email = await sync_to_async(_resolve_to_email)(other_user)

#         rows = await sync_to_async(run_query)(
#             """
#             SELECT
#                 d.id,
#                 d.sender_email,
#                 d.recipient_email,
#                 d.body,
#                 d.created_at,
#                 u.full_name
#             FROM dm_messages d
#             LEFT JOIN users u ON u.email = d.sender_email
#             WHERE d.workspace_id = %s
#               AND (
#                     (d.sender_email = %s AND d.recipient_email = %s)
#                  OR (d.sender_email = %s AND d.recipient_email = %s)
#               )
#             ORDER BY d.created_at ASC
#             LIMIT %s
#             """,
#             (
#                 workspace_id,
#                 self.user_email,
#                 other_email,
#                 other_email,
#                 self.user_email,
#                 limit,
#             ),
#             fetchall=True,
#         )

#         messages = [
#             {
#                 "id": r["id"],
#                 "sender_email": r["sender_email"],
#                 "sender_name": r["full_name"] or r["sender_email"],
#                 "recipient": r["recipient_email"],
#                 "body": r["body"],
#                 "created_at": r["created_at"].isoformat(),
#             }
#             for r in rows or []
#         ]

#         await self.send_json(
#             {
#                 "event": "dm_history",
#                 "messages": messages,
#             }
#         )

#     # =====================================================
#     # GROUP FORWARDERS
#     # =====================================================

#     async def chat_message(self, event: Dict[str, Any]) -> None:
#         await self.send_json(event["data"])

#     async def dm_message(self, event: Dict[str, Any]) -> None:
#         await self.send_json(event["data"])

#     # =====================================================
#     # DISCONNECT (SAFE)
#     # =====================================================

#     async def disconnect(self, close_code: int) -> None:
#         async def safe_discard(group_name: str):
#             try:
#                 await asyncio.wait_for(
#                     self.channel_layer.group_discard(
#                         group_name,
#                         self.channel_name,
#                     ),
#                     timeout=1.0,
#                 )
#             except Exception:
#                 pass

#         if hasattr(self, "group_name"):
#             await safe_discard(self.group_name)

#         if hasattr(self, "dm_group_name"):
#             await safe_discard(self.dm_group_name)





class ChatConsumer(BaseAuthedConsumer):
    """
    WebSocket consumer for:
    - Workspace channel chat
    - Direct messages (DM)
    """

    # =====================================================
    # LIFECYCLE
    # =====================================================

    async def connect(self) -> None:
        await super().connect()
        if getattr(self, "user", None):
            await self._ensure_dm_identity()

    # =====================================================
    # HELPERS
    # =====================================================

    async def _get_sender_name(self, email: str) -> str:
        row = await sync_to_async(run_query)(
            "SELECT full_name FROM users WHERE email=%s",
            (email,),
            fetchone=True,
        )
        return row["full_name"] if row and row.get("full_name") else email

    async def _ensure_dm_identity(self) -> None:
        if hasattr(self, "user_email"):
            return

        email = await sync_to_async(_resolve_to_email)(self.user)
        self.user_email = email or self.user
        self.dm_group_name = _safe_dm_group_for_email(self.user_email)

        await self.channel_layer.group_add(
            self.dm_group_name,
            self.channel_name,
        )

    # =====================================================
    # ROUTER
    # =====================================================

    async def handle_action(self, action: str, data: Dict[str, Any]) -> None:
        if action == "join":
            await self._handle_join(data)
        elif action == "send":
            await self._handle_send(data)
        elif action == "sync_history":
            await self._handle_sync_history(data)
        elif action == "dm_send":
            await self._handle_dm_send(data)
        elif action == "dm_history":
            await self._handle_dm_history(data)
        else:
            await self.send_json({
                "event": "error",
                "message": "Invalid action",
                "received": action,
            })

    # =====================================================
    # CHANNEL CHAT (UNCHANGED)
    # =====================================================

    async def _handle_join(self, data: Dict[str, Any]) -> None:
        try:
            self.channel_id = int(data.get("channel_id"))
        except (TypeError, ValueError):
            await self.send_json({
                "event": "error",
                "message": "Invalid channel_id",
            })
            return

        self.group_name = f"chat_{self.channel_id}"

        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name,
        )

    async def _handle_send(self, data: Dict[str, Any]) -> None:
        if not hasattr(self, "channel_id"):
            return

        body = (data.get("body") or "").strip()
        if not body:
            return

        sender_email = (
            self.user_email
            if hasattr(self, "user_email")
            else await sync_to_async(_resolve_to_email)(self.user)
        )

        sender_name = await self._get_sender_name(sender_email)

        msg_id = await sync_to_async(insert_and_get_id)(
            """
            INSERT INTO messages (channel_id, sender_email, body)
            VALUES (%s, %s, %s)
            """,
            (self.channel_id, sender_email, body),
        )

        payload = {
            "event": "message",
            "id": msg_id,
            "channel_id": self.channel_id,
            "sender_email": sender_email,
            "sender_name": sender_name,
            "body": body,
            "created_at": datetime.datetime.utcnow().isoformat() + "Z",
        }

        await self.channel_layer.group_send(
            self.group_name,
            {"type": "chat.message", "data": payload},
        )

    async def _handle_sync_history(self, data: Dict[str, Any]) -> None:
        try:
            channel_id = int(data.get("channel_id"))
        except (TypeError, ValueError):
            return

        limit = min(int(data.get("limit", 50)), 100)

        rows = await sync_to_async(run_query)(
            """
            SELECT
                m.id,
                m.sender_email,
                m.body,
                m.created_at,
                u.full_name
            FROM messages m
            LEFT JOIN users u ON u.email = m.sender_email
            WHERE m.channel_id = %s
            ORDER BY m.created_at ASC
            LIMIT %s
            """,
            (channel_id, limit),
            fetchall=True,
        )

        messages = [
            {
                "id": r["id"],
                "sender_email": r["sender_email"],
                "sender_name": r["full_name"] or r["sender_email"],
                "body": r["body"],
                "created_at": r["created_at"].isoformat(),
            }
            for r in rows or []
        ]

        await self.send_json({
            "event": "history",
            "messages": messages,
        })

    # =====================================================
    # DIRECT MESSAGES (UPDATED WITH NOTIFICATIONS)
    # =====================================================

    async def _handle_dm_send(self, data: Dict[str, Any]) -> None:
        await self._ensure_dm_identity()

        body = (data.get("body") or "").strip()
        workspace_id = data.get("workspace_id")
        other_user = data.get("other_user")

        if not body or not workspace_id or not other_user:
            return

        sender_email = self.user_email
        sender_name = await self._get_sender_name(sender_email)
        recipient_email = await sync_to_async(_resolve_to_email)(other_user)

        dm_id = await sync_to_async(insert_and_get_id)(
            """
            INSERT INTO dm_messages
                (workspace_id, sender_email, recipient_email, body)
            VALUES (%s, %s, %s, %s)
            """,
            (workspace_id, sender_email, recipient_email, body),
        )

        payload = {
            "event": "dm_message",
            "id": dm_id,
            "workspace_id": workspace_id,
            "sender_email": sender_email,
            "sender_name": sender_name,
            "recipient": recipient_email,
            "body": body,
            "created_at": datetime.datetime.utcnow().isoformat() + "Z",
        }

        # Send DM to both users
        await self.channel_layer.group_send(
            _safe_dm_group_for_email(sender_email),
            {"type": "dm.message", "data": payload},
        )

        await self.channel_layer.group_send(
            _safe_dm_group_for_email(recipient_email),
            {"type": "dm.message", "data": payload},
        )

        # 🔔 DM NOTIFICATION (recipient only)
        if recipient_email != sender_email:
            notif_id = await sync_to_async(run_query)(
                """
                INSERT INTO notifications (user_email, type, payload)
                VALUES (%s, %s, %s)
                """,
                (
                    recipient_email,
                    "dm_message",
                    json.dumps({
                        "title": "New Direct Message",
                        "message": f"{sender_name}: {body[:50]}",
                    }),
                ),
                return_last_id=True,
            )

            await sync_to_async(broadcast_notification)(
                recipient_email,
                {
                    "event": "notification",
                    "id": notif_id,
                    "type": "dm_message",
                    "payload": {
                        "title": "New Direct Message",
                        "message": f"{sender_name}: {body[:50]}",
                    },
                    "created_at": datetime.datetime.utcnow().isoformat() + "Z",
                },
            )

    async def _handle_dm_history(self, data: Dict[str, Any]) -> None:
        await self._ensure_dm_identity()

        workspace_id = data.get("workspace_id")
        other_user = data.get("other_user")
        limit = min(int(data.get("limit", 50)), 100)

        if not workspace_id or not other_user:
            return

        other_email = await sync_to_async(_resolve_to_email)(other_user)

        rows = await sync_to_async(run_query)(
            """
            SELECT
                d.id,
                d.sender_email,
                d.recipient_email,
                d.body,
                d.created_at,
                u.full_name
            FROM dm_messages d
            LEFT JOIN users u ON u.email = d.sender_email
            WHERE d.workspace_id = %s
              AND (
                    (d.sender_email = %s AND d.recipient_email = %s)
                 OR (d.sender_email = %s AND d.recipient_email = %s)
              )
            ORDER BY d.created_at ASC
            LIMIT %s
            """,
            (
                workspace_id,
                self.user_email,
                other_email,
                other_email,
                self.user_email,
                limit,
            ),
            fetchall=True,
        )

        messages = [
            {
                "id": r["id"],
                "sender_email": r["sender_email"],
                "sender_name": r["full_name"] or r["sender_email"],
                "recipient": r["recipient_email"],
                "body": r["body"],
                "created_at": r["created_at"].isoformat(),
            }
            for r in rows or []
        ]

        await self.send_json({
            "event": "dm_history",
            "messages": messages,
        })

    # =====================================================
    # FORWARDERS
    # =====================================================

    async def chat_message(self, event: Dict[str, Any]) -> None:
        await self.send_json(event["data"])

    async def dm_message(self, event: Dict[str, Any]) -> None:
        await self.send_json(event["data"])

    # =====================================================
    # DISCONNECT
    # =====================================================

    async def disconnect(self, close_code: int) -> None:
        async def safe_discard(group_name: str):
            try:
                await asyncio.wait_for(
                    self.channel_layer.group_discard(
                        group_name,
                        self.channel_name,
                    ),
                    timeout=1.0,
                )
            except Exception:
                pass

        if hasattr(self, "group_name"):
            await safe_discard(self.group_name)

        if hasattr(self, "dm_group_name"):
            await safe_discard(self.dm_group_name)


# ==========================================================
# 🔔 Activity Feed CONSUMER (REFINED)
# ==========================================================

class ActivityFeedConsumer(AsyncWebsocketConsumer):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user_email = None
        self.workspace_id = None
        self.group_name = None

    async def connect(self):
        # 🔓 Always accept WebSocket
        await self.accept()

        await self.send_json({
            "event": "connected",
            "message": "Send join action"
        })

    async def receive(self, text_data=None, bytes_data=None):
        try:
            payload = json.loads(text_data or "{}")
        except json.JSONDecodeError:
            await self.send_json({"event": "error", "message": "Invalid JSON"})
            return

        if payload.get("action") == "join":
            await self.join_workspace(payload)
            return

        await self.send_json({"event": "error", "message": "Unsupported action"})

    async def join_workspace(self, payload):
        workspace_id = payload.get("workspace_id")

        if not workspace_id:
            await self.send_json({
                "event": "error",
                "message": "workspace_id required"
            })
            return

        # 🔐 Read JWT from cookies
        cookie_header = dict(self.scope.get("headers", [])).get(b"cookie")
        if not cookie_header:
            await self.send_json({
                "event": "error",
                "message": "Authentication required"
            })
            return

        cookies = SimpleCookie()
        cookies.load(cookie_header.decode())

        access_cookie = cookies.get("access_token")
        if not access_cookie:
            await self.send_json({
                "event": "error",
                "message": "Access token missing"
            })
            return

        try:
            payload = decode_token(access_cookie.value)
            self.user_email = payload.get("sub")
        except Exception:
            await self.send_json({
                "event": "error",
                "message": "Invalid or expired token"
            })
            return

        # Join group
        if self.group_name:
            await self.channel_layer.group_discard(
                self.group_name,
                self.channel_name
            )

        self.workspace_id = int(workspace_id)
        self.group_name = f"activity_{self.workspace_id}"

        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )

        await self.send_json({
            "event": "joined",
            "workspace_id": self.workspace_id,
            "user": self.user_email
        })

    async def activity_message(self, event):
        await self.send_json(event.get("data", {}))

    async def disconnect(self, code):
        if self.group_name:
            await self.channel_layer.group_discard(
                self.group_name,
                self.channel_name
            )

    async def send_json(self, data):
        await self.send(text_data=json.dumps(data))

# ==========================================================
# 🟢 PRESENCE CONSUMER
# ==========================================================


class PresenceConsumer(BaseAuthedConsumer):
    """
    Tracks user online/offline/idle state and broadcasts updates.

    Supported actions:
      - { "action": "status", "status": "online" | "idle" | "offline" }
      - { "action": "ping" }
    """

    async def connect(self) -> None:
        # Use BaseAuthedConsumer connect logic
        await super().connect()
        if not getattr(self, "user", None):
            return

        # Single global presence group (you can later make it per-workspace)
        self.group_name = "presence_all"
        await self.channel_layer.group_add(self.group_name, self.channel_name)

        # mark online in DB
        await sync_to_async(run_query)(
            "INSERT INTO presence (user_email, status, last_seen) "
            "VALUES (%s,'online',NOW()) "
            "ON DUPLICATE KEY UPDATE status='online', last_seen=NOW()",
            (self.user,),
        )
        logger.info("[Presence] %s online", self.user)

        # broadcast presence update
        await self.channel_layer.group_send(
            self.group_name,
            {
                "type": "presence.update",
                "data": {
                    "event": "presence_update",
                    "user": self.user,
                    "status": "online",
                    "last_seen": datetime.datetime.utcnow().isoformat() + "Z",
                },
            },
        )

    async def handle_action(
        self,
        action: str,
        data: Dict[str, Any],
    ) -> None:
        if action == "status":
            await self._handle_status(data)
        elif action == "ping":
            await self.send_json(
                {
                    "event": "pong",
                    "ts": datetime.datetime.utcnow().isoformat() + "Z",
                }
            )
        else:
            await self.send_error(
                "Invalid action",
                code="invalid_action",
                extra={"received": action},
            )

    async def _handle_status(self, data: Dict[str, Any]) -> None:
        status = (data.get("status") or "online").lower()
        if status not in {"online", "idle", "offline"}:
            status = "online"

        await sync_to_async(run_query)(
            "UPDATE presence SET status=%s, last_seen=NOW() WHERE user_email=%s",
            (status, self.user),
        )
        logger.info(
            "[Presence] %s updated status -> %s",
            self.user,
            status,
        )

        await self.channel_layer.group_send(
            self.group_name,
            {
                "type": "presence.update",
                "data": {
                    "event": "presence_update",
                    "user": self.user,
                    "status": status,
                    "last_seen": datetime.datetime.utcnow().isoformat() + "Z",
                },
            },
        )

    async def presence_update(self, event: Dict[str, Any]) -> None:
        await self.send_json(event["data"])

    async def disconnect(self, close_code: int) -> None:
        try:
            await sync_to_async(run_query)(
                "UPDATE presence SET status='offline', last_seen=NOW() WHERE user_email=%s",
                (self.user,),
            )
            logger.info("[Presence] %s disconnected", self.user)

            # broadcast offline to others
            if hasattr(self, "group_name"):
                await self.channel_layer.group_send(
                    self.group_name,
                    {
                        "type": "presence.update",
                        "data": {
                            "event": "presence_update",
                            "user": self.user,
                            "status": "offline",
                            "last_seen": datetime.datetime.utcnow().isoformat() + "Z",
                        },
                    },
                )

            if hasattr(self, "group_name"):
                await self.channel_layer.group_discard(
                    self.group_name, self.channel_name
                )
        except Exception as e:
            logger.exception("[Presence] disconnect error: %s", e)


# ==========================================================
# 🔔 NOTIFICATIONS CONSUMER (NEW)
# ==========================================================

class NotificationConsumer(AsyncWebsocketConsumer):
    """
    Real-time notification consumer.

    - Auto subscribes on connect
    - No polling
    - No fetch required
    - DB persistence + WS push
    """

    async def connect(self):
        self.user = self.scope.get("user_email")

        if not self.user:
            logger.warning("[NOTIFY][CONNECT][DENIED]")
            await self.close(code=4403)
            return

        await self.accept()

        # ✅ SAFE GROUP NAME (THIS IS THE KEY FIX)
        self.group_name = f"notifications_{safe_group_name(self.user)}"

        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )

        logger.info(
            "[NOTIFY][CONNECTED] user=%s group=%s",
            self.user,
            self.group_name
        )

        await self.send_json({
            "event": "connected",
            "message": "Notification socket connected"
        })

    async def receive(self, text_data=None, bytes_data=None):
        """
        - join / subscribe : no-op (already subscribed)
        - notify           : dev / Postman testing only
        """
        try:
            data = json.loads(text_data or "{}")
            action = data.get("action")

            # -----------------------------
            # JOIN / SUBSCRIBE (SAFE NO-OP)
            # -----------------------------
            if action in ("join", "subscribe"):
                await self.send_json({
                    "event": "subscribed",
                    "user": self.user
                })
                return

            # -----------------------------
            # DEV / TEST NOTIFICATION
            # -----------------------------
            if action == "notify":
                notif_type = data.get("type", "system")
                payload = data.get("payload", {})

                logger.info(
                    "[NOTIFY][TEST_SEND] user=%s type=%s",
                    self.user,
                    notif_type
                )

                await sync_to_async(run_query)(
                    """
                    INSERT INTO notifications (user_email, type, payload)
                    VALUES (%s, %s, %s)
                    """,
                    (self.user, notif_type, json.dumps(payload)),
                )

                await self.channel_layer.group_send(
                    self.group_name,
                    {
                        "type": "notification_message",
                        "data": {
                            "event": "notification",
                            "type": notif_type,
                            "payload": payload,
                            "created_at": datetime.datetime.utcnow().isoformat() + "Z",
                        },
                    },
                )
                return

            # -----------------------------
            # INVALID ACTION
            # -----------------------------
            await self.send_json({
                "event": "error",
                "code": "invalid_action",
                "message": "Invalid action",
                "received": action,
            })

        except Exception:
            logger.exception(
                "[NOTIFY][RECEIVE][ERROR] user=%s",
                getattr(self, "user", None)
            )
            await self.send_json({
                "event": "error",
                "message": "Internal error"
            })

    # 🔥 THIS IS CALLED BY broadcast_notification()
    async def notification_message(self, event):
        await self.send_json(event["data"])

    async def disconnect(self, code):
        if hasattr(self, "group_name"):
            await self.channel_layer.group_discard(
                self.group_name,
                self.channel_name
            )

        logger.info(
            "[NOTIFY][DISCONNECT] user=%s code=%s",
            getattr(self, "user", None),
            code
        )

    async def send_json(self, data):
        await self.send(text_data=json.dumps(data))

