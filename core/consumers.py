import json
import datetime
import logging
from urllib.parse import parse_qs
from typing import Optional, Dict, Any

from channels.generic.websocket import AsyncWebsocketConsumer
from asgiref.sync import sync_to_async
from db import get_last_insert_id, insert_and_get_id
from db import run_query, is_refresh_revoked
from jwt_utils import _resolve_to_email, _user_is_member_of_workspace, decode_token

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
            await self.close(code=403)
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
            await self.close(code=403)
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


class ChatConsumer(BaseAuthedConsumer):
    """
    Real-time chat consumer.

    Supported actions:
      - { "action": "join", "channel_id": 1 }
      - { "action": "send", "channel_id": 1, "body": "Hello team" }
      - { "action": "typing", "channel_id": 1, "is_typing": true }
      - { "action": "read_receipt", "message_id": 123 }
      - { "action": "sync_history", "channel_id": 1, "limit": 20 }
      - { "action": "ping" }

      # Direct messages (DM)
      - { "action": "dm_send", "workspace_id": 1, "other_user": "khan", "body": "hi" }
      - { "action": "dm_edit", "id": 10, "body": "updated text" }
      - { "action": "dm_delete", "id": 10 }
    """

    # ---------- small internal helper ----------

    async def _ensure_dm_identity(self) -> None:
        """
        Ensure we have self.user_email and self.dm_group_name and that
        this connection is subscribed to the personal DM group.
        """
        if hasattr(self, "user_email"):
            return

        # self.user is set by BaseAuthedConsumer (username or email)
        email = await sync_to_async(_resolve_to_email)(self.user)
        if not email:
            # fallback: use username as email-ish (not ideal but avoids crash)
            email = self.user

        self.user_email = email
        self.dm_group_name = _safe_dm_group_for_email(self.user_email)

        await self.channel_layer.group_add(self.dm_group_name, self.channel_name)
        logger.info("[DM] %s joined DM group %s", self.user_email, self.dm_group_name)

    # ---------- main action router ----------

    async def handle_action(
        self,
        action: str,
        data: Dict[str, Any],
    ) -> None:
        if action == "join":
            await self._handle_join(data)
        elif action == "send":
            await self._handle_send(data)
        elif action == "typing":
            await self._handle_typing(data)
        elif action == "read_receipt":
            await self._handle_read_receipt(data)
        elif action == "sync_history":
            await self._handle_sync_history(data)
        elif action == "ping":
            await self.send_json(
                {
                    "event": "pong",
                    "ts": datetime.datetime.utcnow().isoformat() + "Z",
                }
            )

        # ----- DM actions -----
        elif action == "dm_send":
            await self._handle_dm_send(data)
        elif action == "dm_edit":
            await self._handle_dm_edit(data)
        elif action == "dm_delete":
            await self._handle_dm_delete(data)

        else:
            await self.send_error(
                "Invalid action",
                code="invalid_action",
                extra={"received": action},
            )

    # ---------- existing helpers (channels) ----------

    async def _handle_join(self, data: Dict[str, Any]) -> None:
        try:
            self.channel_id = int(data.get("channel_id"))
        except (TypeError, ValueError):
            await self.send_error(
                "Invalid or missing channel_id", code="invalid_channel"
            )
            return

        self.group_name = "chat_%s" % self.channel_id
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        logger.info("[Chat] %s joined group %s", self.user, self.group_name)

        await self.send_json({"event": "joined", "channel_id": self.channel_id})

    async def _handle_send(self, data: Dict[str, Any]) -> None:
        if not hasattr(self, "channel_id"):
            await self.send_error("Join a channel first", code="not_in_channel")
            return

        body = (data.get("body") or "").strip()
        if not body:
            await self.send_error("Empty message", code="empty_message")
            return

        # store message
         # store message
   # store message and get id in ONE helper
        msg_id = await sync_to_async(insert_and_get_id)(
            "INSERT INTO messages (channel_id, sender_email, body) VALUES (%s,%s,%s)",
            (self.channel_id, self.user, body),
        )



        payload: Dict[str, Any] = {
            "event": "message",
            "id": msg_id,
            "sender": self.user,
            "body": body,
            "channel_id": self.channel_id,
            "created_at": datetime.datetime.utcnow().isoformat() + "Z",
        }

        # Broadcast message to channel
        await self.channel_layer.group_send(
            self.group_name,
            {"type": "chat.message", "data": payload},
        )

    async def _handle_typing(self, data: Dict[str, Any]) -> None:
        if not hasattr(self, "channel_id"):
            await self.send_error("Join a channel first", code="not_in_channel")
            return

        is_typing = bool(data.get("is_typing", True))
        payload: Dict[str, Any] = {
            "event": "typing",
            "channel_id": self.channel_id,
            "user": self.user,
            "is_typing": is_typing,
        }
        await self.channel_layer.group_send(
            self.group_name,
            {"type": "chat.typing", "data": payload},
        )

    async def _handle_read_receipt(self, data: Dict[str, Any]) -> None:
        try:
            message_id = int(data.get("message_id"))
        except (TypeError, ValueError):
            await self.send_error(
                "Invalid or missing message_id",
                code="invalid_message_id",
            )
            return

        # store read event (best-effort, ignore failures)
        try:
            await sync_to_async(run_query)(
                """
                INSERT INTO message_reads (message_id, reader_email, read_at)
                VALUES (%s,%s,NOW())
                ON DUPLICATE KEY UPDATE read_at = NOW()
                """,
                (message_id, self.user),
            )
        except Exception as e:
            logger.exception("[Chat] read_receipt DB error: %s", e)

        payload: Dict[str, Any] = {
            "event": "read_receipt",
            "message_id": message_id,
            "reader": self.user,
            "read_at": datetime.datetime.utcnow().isoformat() + "Z",
        }
        if hasattr(self, "group_name"):
            await self.channel_layer.group_send(
                self.group_name,
                {"type": "chat.read_receipt", "data": payload},
            )
        else:
            await self.send_json(payload)

    async def _handle_sync_history(self, data: Dict[str, Any]) -> None:
        try:
            channel_id = int(data.get("channel_id"))
        except (TypeError, ValueError):
            await self.send_error(
                "Invalid or missing channel_id", code="invalid_channel"
            )
            return

        limit = data.get("limit") or 20
        try:
            limit = max(1, min(int(limit), 100))
        except (TypeError, ValueError):
            limit = 20

        rows = await sync_to_async(run_query)(
            """
            SELECT id, sender_email, body, created_at
            FROM messages
            WHERE channel_id=%s
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (channel_id, limit),
            fetchall=True,
        )

        messages = []
        for r in reversed(rows or []):
            created_at = r["created_at"]
            created_str = (
                created_at.isoformat()
                if hasattr(created_at, "isoformat")
                else str(created_at)
            )

            messages.append(
                {
                    "id": r["id"],
                    "sender": r["sender_email"],
                    "body": r["body"],
                    "channel_id": channel_id,
                    "created_at": created_str,
                }
            )

        await self.send_json(
            {
                "event": "history",
                "channel_id": channel_id,
                "messages": messages,
            }
        )

    # ---------- DM handlers ----------

    async def _handle_dm_send(self, data: Dict[str, Any]) -> None:
        """
        { "action": "dm_send", "workspace_id": 1, "other_user": "khan", "body": "hi" }
        """
        await self._ensure_dm_identity()

        ws_id = data.get("workspace_id")
        other_identifier = data.get("other_user")
        body = (data.get("body") or "").strip()

        try:
            ws_id = int(ws_id)
        except (TypeError, ValueError):
            ws_id = None

        if not ws_id or not other_identifier or not body:
            await self.send_json(
                {
                    "event": "dm_error",
                    "message": "workspace_id, other_user and body are required",
                }
            )
            return

        sender_email = self.user_email
        recipient_email = await sync_to_async(_resolve_to_email)(other_identifier)

        if not recipient_email:
            await self.send_json(
                {
                    "event": "dm_error",
                    "message": "Could not resolve other_user email",
                }
            )
            return

        # Membership checks (strict private DM: no admin override)
        sender_member = await sync_to_async(_user_is_member_of_workspace)(
            sender_email, ws_id
        )
        if not sender_member:
            await self.send_json(
                {
                    "event": "dm_error",
                    "message": "Forbidden: sender not in workspace",
                }
            )
            return

        recipient_member = await sync_to_async(_user_is_member_of_workspace)(
            recipient_email, ws_id
        )
        if not recipient_member:
            await self.send_json(
                {
                    "event": "dm_error",
                    "message": "Other user not in this workspace",
                }
            )
            return
    
                # Insert message
       # Insert message and get id in one call
         # Insert message and get id in ONE helper
        dm_id = await sync_to_async(insert_and_get_id)(
            """
            INSERT INTO dm_messages (workspace_id, sender_email, recipient_email, body)
            VALUES (%s, %s, %s, %s)
            """,
            (ws_id, sender_email, recipient_email, body),
        )

        logger.info(
            "[DM_WS] Inserted dm_messages row: id=%s, ws_id=%s, sender=%s, recipient=%s",
            dm_id,
            ws_id,
            sender_email,
            recipient_email,
        )

        ts = datetime.datetime.utcnow().isoformat() + "Z"


        payload: Dict[str, Any] = {
            "event": "dm_message",
            "id": dm_id,
            "workspace_id": ws_id,
            "sender": sender_email,
            "recipient": recipient_email,
            "body": body,
            "is_edited": False,
            "created_at": ts,
        }

        event = {"type": "dm.message", "data": payload}

        sender_group = _safe_dm_group_for_email(sender_email)
        recipient_group = _safe_dm_group_for_email(recipient_email)

        await self.channel_layer.group_send(sender_group, event)
        await self.channel_layer.group_send(recipient_group, event)

    async def _handle_dm_edit(self, data: Dict[str, Any]) -> None:
        """
        { "action": "dm_edit", "id": 10, "body": "new text" }
        """
        await self._ensure_dm_identity()

        dm_id = data.get("id")
        new_body = (data.get("body") or "").strip()

        try:
            dm_id = int(dm_id)
        except (TypeError, ValueError):
            dm_id = None

        if not dm_id or not new_body:
            await self.send_json(
                {
                    "event": "dm_error",
                    "message": "id and body are required for dm_edit",
                }
            )
            return

        current_email = self.user_email

        row = await sync_to_async(run_query)(
            """
            SELECT id, workspace_id, sender_email, recipient_email, body
            FROM dm_messages
            WHERE id = %s
            """,
            (dm_id,),
            fetchone=True,
        )

        if not row:
            await self.send_json({"event": "dm_error", "message": "DM not found"})
            return

        if isinstance(row, dict):
            ws_id = row["workspace_id"]
            sender_email = row["sender_email"]
            recipient_email = row["recipient_email"]
        else:
            _, ws_id, sender_email, recipient_email, _ = row

        # Only sender can edit
        if current_email != sender_email:
            await self.send_json(
                {
                    "event": "dm_error",
                    "message": "Forbidden: only sender can edit",
                }
            )
            return

        await sync_to_async(run_query)(
            """
            UPDATE dm_messages
            SET body = %s, is_edited = 1
            WHERE id = %s
            """,
            (new_body, dm_id),
        )

        ts = datetime.datetime.utcnow().isoformat() + "Z"

        payload: Dict[str, Any] = {
            "event": "dm_edit",
            "id": dm_id,
            "workspace_id": ws_id,
            "sender": sender_email,
            "recipient": recipient_email,
            "body": new_body,
            "is_edited": True,
            "updated_at": ts,
        }

        event = {"type": "dm.edit", "data": payload}

        sender_group = _safe_dm_group_for_email(sender_email)
        recipient_group = _safe_dm_group_for_email(recipient_email)

        await self.channel_layer.group_send(sender_group, event)
        await self.channel_layer.group_send(recipient_group, event)

    async def _handle_dm_delete(self, data: Dict[str, Any]) -> None:
        """
        { "action": "dm_delete", "id": 10 }
        """
        await self._ensure_dm_identity()

        dm_id = data.get("id")
        try:
            dm_id = int(dm_id)
        except (TypeError, ValueError):
            dm_id = None

        if not dm_id:
            await self.send_json(
                {
                    "event": "dm_error",
                    "message": "id required for dm_delete",
                }
            )
            return

        current_email = self.user_email

        row = await sync_to_async(run_query)(
            """
            SELECT id, workspace_id, sender_email, recipient_email, body
            FROM dm_messages
            WHERE id = %s
            """,
            (dm_id,),
            fetchone=True,
        )

        if not row:
            await self.send_json({"event": "dm_error", "message": "DM not found"})
            return

        if isinstance(row, dict):
            ws_id = row["workspace_id"]
            sender_email = row["sender_email"]
            recipient_email = row["recipient_email"]
        else:
            _, ws_id, sender_email, recipient_email, _ = row

        # Only sender can delete
        if current_email != sender_email:
            await self.send_json(
                {
                    "event": "dm_error",
                    "message": "Forbidden: only sender can delete",
                }
            )
            return

        await sync_to_async(run_query)(
            "DELETE FROM dm_messages WHERE id = %s",
            (dm_id,),
        )

        payload: Dict[str, Any] = {
            "event": "dm_delete",
            "id": dm_id,
            "workspace_id": ws_id,
        }

        event = {"type": "dm.delete", "data": payload}

        sender_group = _safe_dm_group_for_email(sender_email)
        recipient_group = _safe_dm_group_for_email(recipient_email)

        await self.channel_layer.group_send(sender_group, event)
        await self.channel_layer.group_send(recipient_group, event)

    # ---------- group handlers ----------

    async def chat_message(self, event: Dict[str, Any]) -> None:
        await self.send_json(event["data"])

    async def chat_typing(self, event: Dict[str, Any]) -> None:
        await self.send_json(event["data"])

    async def chat_read_receipt(self, event: Dict[str, Any]) -> None:
        await self.send_json(event["data"])

    async def dm_message(self, event: Dict[str, Any]) -> None:
        await self.send_json(event["data"])

    async def dm_edit(self, event: Dict[str, Any]) -> None:
        await self.send_json(event["data"])

    async def dm_delete(self, event: Dict[str, Any]) -> None:
        await self.send_json(event["data"])

    async def disconnect(self, close_code: int) -> None:
        try:
            if hasattr(self, "group_name"):
                await self.channel_layer.group_discard(
                    self.group_name, self.channel_name
                )
            if hasattr(self, "dm_group_name"):
                await self.channel_layer.group_discard(
                    self.dm_group_name, self.channel_name
                )
            logger.info(
                "[Chat] %s disconnected",
                getattr(self, "user", "unknown"),
            )
        except Exception as e:
            logger.exception("[Chat] disconnect error: %s", e)


# ==========================================================
class ActivityFeedConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user = get_user_from_scope(self.scope)

        if not self.user:
            await self.close(code=403)
            return

        await self.accept()
        self.group_name = None

    async def receive(self, text_data):
        try:
            data = json.loads(text_data or "{}")
            action = data.get("action")

            # ----------------------------------------
            # JOIN workspace activity stream
            # ----------------------------------------
            if action == "join":
                ws_id = int(data.get("workspace_id"))
                self.group_name = f"activity_{ws_id}"

                await self.channel_layer.group_add(self.group_name, self.channel_name)

                await self.send_json({"event": "joined", "workspace_id": ws_id})
                return

            # ----------------------------------------
            # SIMULATE ACTIVITY (Postman testing)
            # ----------------------------------------
            if action == "simulate_activity":
                ws_id = int(data.get("workspace_id"))
                summary = data.get("summary") or "Activity"

                # Save into DB
                await sync_to_async(run_query)(
                    """
                    INSERT INTO activities (workspace_id, actor_email, type, summary)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (ws_id, self.user, "test_event", summary),
                )

                payload = {
                    "event": "activity",
                    "workspace_id": ws_id,
                    "summary": summary,
                    "actor": self.user,
                    "created_at": datetime.datetime.utcnow().isoformat() + "Z",
                }

                # broadcast
                await self.channel_layer.group_send(
                    f"activity_{ws_id}", {"type": "activity.message", "data": payload}
                )
                return

            # ----------------------------------------
            # Invalid
            # ----------------------------------------
            await self.send_json(
                {
                    "event": "error",
                    "code": "invalid_action",
                    "message": "Invalid action",
                    "received": action,
                }
            )

        except Exception as e:
            logger.exception("[Activity] Error: %s", e)
            await self.send_json({"event": "error", "message": str(e)})

    async def activity_message(self, event):
        await self.send_json(event["data"])

    async def disconnect(self, code):
        if self.group_name:
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

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
    async def connect(self):
        self.user = get_user_from_scope(self.scope)

        if not self.user:
            await self.close(code=403)
            return

        await self.accept()

        # User-specific group
        self.group_name = f"notify_{self.user}"
        await self.channel_layer.group_add(self.group_name, self.channel_name)

    async def receive(self, text_data):
        try:
            data = json.loads(text_data or "{}")
            action = data.get("action")

            # -------------------------------------
            # SEND NOTIFICATION (Postman test)
            # -------------------------------------
            if action == "notify":
                notif_type = data.get("type", "system")
                payload = data.get("payload", {})

                # Save into DB
                await sync_to_async(run_query)(
                    """
                    INSERT INTO notifications (user_email, type, payload)
                    VALUES (%s, %s, %s)
                    """,
                    (self.user, notif_type, json.dumps(payload)),
                )

                # Broadcast to user
                await self.channel_layer.group_send(
                    self.group_name,
                    {
                        "type": "notification.message",
                        "data": {
                            "event": "notification",
                            "type": notif_type,
                            "payload": payload,
                            "created_at": datetime.datetime.utcnow().isoformat() + "Z",
                        },
                    },
                )
                return

            await self.send_json(
                {
                    "event": "error",
                    "code": "invalid_action",
                    "message": "Invalid action",
                    "received": action,
                }
            )

        except Exception as e:
            logger.exception("[Notify] Error: %s", e)
            await self.send_json({"event": "error", "message": str(e)})

    async def notification_message(self, event):
        await self.send_json(event["data"])

    async def disconnect(self, code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def send_json(self, data):
        await self.send(text_data=json.dumps(data))
