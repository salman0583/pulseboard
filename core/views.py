# core/views.py
import email
import json
import hashlib
import logging
import opcode
import secrets
import hmac

from MySQLdb import IntegrityError
import requests
from jwt_utils import (
    _broadcast_activity,
    _resolve_to_email,
    broadcast_notification,
    can_assign_leader,
    can_manage_workspace,
    decode_token,
    get_current_user,
    initial_repo_sync,
    is_super_admin,
    revoke_refresh_token,
    broadcast_notification,
)
from django.conf import settings
from django.utils import timezone
from django.http import JsonResponse
import datetime as datetime
import random
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

# Decorators
from core.decorators import require_access_token
from django.conf import settings

# DB helpers
from db import run_query, save_refresh_token, revoke_refresh_token, get_last_insert_id

# JWT / helper utilities
from jwt_utils import (
    _can_create_workspace,
    _get_default_workspace_id,
    _get_workspace_role,
    _is_workspace_member,
    _is_workspace_leader,
    _is_admin,
    _is_workspace_owner,
    _user_is_owner_of_workspace,
    _get_current_user_email,
    _insert_activity,
    get_request_data,
    decode_token,
    create_access_token,
    create_refresh_token,
    create_id_token,
    is_refresh_revoked,
    _insert_notification,
    _get_workspace_for_channel,
    _send_notification_email,
    _username_to_email,
    _process_message_mentions,
    is_refresh_revoked,
    _handle_github_event,
    _user_is_owner_of_workspace,
)

logger = logging.getLogger("django")

# -----------------------------------------------------------------------------
# CONFIG
# -----------------------------------------------------------------------------

DEV_MODE = getattr(settings, "DEBUG", True)
COOKIE_KWARGS = {
    "httponly": True,
    "secure": False if DEV_MODE else True,
    "samesite": "Lax" if DEV_MODE else "None",
    "path": "/",
}


# -----------------------------------------------------------------------------
# REGISTER USER
# -----------------------------------------------------------------------------
@csrf_exempt
def register_user(request):
    if request.method != "POST":
        return JsonResponse(
            {"status": "error", "message": "POST required"},
            status=405,
        )

    data = get_request_data(request)

    # Normalize inputs
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    email = (data.get("email") or "").strip().lower()
    full_name = (data.get("full_name") or "").strip()
    phone_number = (data.get("phone_number") or "").strip() or None  # optional

    # Required fields check
    if not username or not password or not email or not full_name:
        return JsonResponse(
            {
                "status": "error",
                "message": "username, password, email and full_name are required",
            },
            status=400,
        )

    # Simple email format check (you can improve later)
    if "@" not in email or "." not in email:
        return JsonResponse(
            {"status": "error", "message": "Invalid email format"},
            status=400,
        )

    # Hash password (same approach you used before, just different column name)
    password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()

    try:
        run_query(
            """
            INSERT INTO users (username, email, password_hash, full_name, phone_number)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (username, email, password_hash, full_name, phone_number),
        )

        return JsonResponse(
            {"status": "success", "message": "User registered!"},
            status=201,
        )

    except Exception as e:
        logger.exception(f"[Register] Error: {e}")
        msg = str(e)

        # Optional: friendlier duplicate messages for MySQL "Duplicate entry"
        if "Duplicate entry" in msg and "for key 'username'" in msg:
            return JsonResponse(
                {"status": "error", "message": "Username already exists"},
                status=400,
            )
        if "Duplicate entry" in msg and "for key 'email'" in msg:
            return JsonResponse(
                {"status": "error", "message": "Email already registered"},
                status=400,
            )

        return JsonResponse(
            {"status": "error", "message": "Registration failed"},
            status=500,
        )


# -----------------------------------------------------------------------------
# REQUEST OTP
# -----------------------------------------------------------------------------


@csrf_exempt
def request_otp(request):
    if request.method != "POST":
        return JsonResponse({"status": "error", "message": "POST required"}, status=405)

    data = get_request_data(request)
    email = data.get("email")

    if not email:
        return JsonResponse(
            {"status": "error", "message": "Email required"}, status=400
        )

    user = run_query(
        "SELECT username, email FROM users WHERE email=%s",
        (email,),
        fetchone=True,
    )

    if not user:
        return JsonResponse(
            {"status": "error", "message": "User not found"}, status=404
        )

    username = user["username"]

    # ✅ remove previous OTPs
    run_query("DELETE FROM otp_codes WHERE username=%s", (username,))

    # ✅ generate new
    import secrets

    otp_code = f"{secrets.randbelow(1000000):06d}"

    run_query(
        "INSERT INTO otp_codes (username, otp_code) VALUES (%s, %s)",
        (username, otp_code),
    )

    logger.info(f"[OTP] generated for {username}: {otp_code}")

    # =====================================================
    # 🧪 TEST MODE → no email
    # =====================================================
    from django.conf import settings

    if settings.OTP_TEST_MODE:
        logger.warning(f"⚠️ TEST MODE OTP for {email}: {otp_code}")
        return JsonResponse(
            {
                "status": "success",
                "message": "OTP generated (test mode)",
                "otp": otp_code,  # optional → remove if you want
            }
        )

    # =====================================================
    # 🚀 PRODUCTION → send email
    # =====================================================
# =====================================================
# 🚀 PRODUCTION → send email using RESEND
# =====================================================
    try:
        import resend
        resend.api_key = settings.RESEND_API_KEY

        resend.Emails.send({
            "from": "PulseBoard <onboarding@resend.dev>",
            "to": [email],
            "subject": "Your OTP Code",
            "html": f"<strong>Your OTP is {otp_code}</strong>",
        })

    except Exception as e:
        logger.exception(f"[OTP EMAIL ERROR] {e}")
        return JsonResponse(
            {"status": "error", "message": "Email failed"},
            status=500,
        )

    return JsonResponse({
        "status": "success",
        "message": "OTP sent successfully"
    })
    # -----------------------------------------------------------------------------
# VERIFY OTP → LOGIN
# -----------------------------------------------------------------------------
from django.conf import settings


@csrf_exempt
def verify_otp(request):
    if request.method != "POST":
        return JsonResponse(
            {"status": "error", "message": "POST required"},
            status=405,
        )

    data = get_request_data(request)
    email = data.get("email")
    otp = data.get("otp")

    if not email or not otp:
        return JsonResponse(
            {"status": "error", "message": "Email and OTP required"},
            status=400,
        )

    try:
        # =====================================================
        # 🔹 Load user
        # =====================================================
        user = run_query(
            """
            SELECT username, email, full_name
            FROM users
            WHERE email = %s AND is_active = 1
            """,
            (email,),
            fetchone=True,
        )

        if not user:
            return JsonResponse(
                {"status": "error", "message": "User not found"},
                status=404,
            )

        username = user["username"]

        # =====================================================
        # 🔹 Fetch latest OTP
        # =====================================================
        otp_record = run_query(
            """
            SELECT otp_code, created_at
            FROM otp_codes
            WHERE username = %s
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (username,),
            fetchone=True,
        )

        if not otp_record:
            return JsonResponse(
                {"status": "error", "message": "OTP not found"},
                status=404,
            )

        db_otp = str(otp_record["otp_code"]).strip()
        entered_otp = str(otp).strip()

        logger.info(f"[OTP VERIFY] user={username} entered={entered_otp} db={db_otp}")

        # =====================================================
        # 🧪 TEST MODE LOGIC
        # =====================================================
        if settings.OTP_TEST_MODE:
            logger.warning("⚠️ OTP TEST MODE ENABLED")

            if entered_otp != db_otp and entered_otp != settings.OTP_MASTER_CODE:
                return JsonResponse(
                    {"status": "error", "message": "Invalid OTP"},
                    status=401,
                )

        # =====================================================
        # 🚀 PRODUCTION LOGIC
        # =====================================================
        else:
            if entered_otp != db_otp:
                return JsonResponse(
                    {"status": "error", "message": "Invalid OTP"},
                    status=401,
                )

        # =====================================================
        # ⏰ EXPIRY CHECK (still required in both modes)
        # =====================================================
        otp_time = otp_record["created_at"].replace(tzinfo=None)
        now = timezone.now().replace(tzinfo=None)

        if now - otp_time > datetime.timedelta(minutes=settings.OTP_EXPIRY_MINUTES):
            return JsonResponse(
                {"status": "error", "message": "OTP expired"},
                status=401,
            )

        # =====================================================
        # ✅ OTP VALID → ISSUE TOKENS
        # =====================================================
        identity = user["email"]

        refresh_token, jti, _ = create_refresh_token(identity)
        access_token = create_access_token(identity, jti=jti)
        id_token = create_id_token(identity, user["email"], user.get("full_name"))

        # Save refresh
        r_payload = decode_token(refresh_token)
        save_refresh_token(jti, identity, r_payload["exp"])

        # Cleanup OTP
        run_query(
            "DELETE FROM otp_codes WHERE username = %s",
            (username,),
        )

        response = JsonResponse({"status": "success", "message": "Login successful!"})

        response.set_cookie(
            "access_token",
            access_token,
            max_age=600,
            **COOKIE_KWARGS,
        )
        response.set_cookie(
            "refresh_token",
            refresh_token,
            max_age=7 * 86400,
            **COOKIE_KWARGS,
        )
        response.set_cookie(
            "id_token",
            id_token,
            max_age=600,
            **COOKIE_KWARGS,
        )

        return response

    except Exception as e:
        logger.exception(e)
        return JsonResponse(
            {"status": "error", "message": "Internal server error"},
            status=500,
        )


# -----------------------------------------------------------------------------
# LOGOUT
# -----------------------------------------------------------------------------


@csrf_exempt
def logout(request):
    if request.method != "POST":
        return JsonResponse(
            {"status": "error", "message": "POST required"},
            status=405,
        )

    try:
        rt = request.COOKIES.get("refresh_token")
        if rt:
            payload = decode_token(rt)
            revoke_refresh_token(payload["jti"])

        response = JsonResponse({"status": "success", "message": "Logged out"})
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")
        response.delete_cookie("id_token")
        return response

    except Exception as e:
        logger.exception(f"[Logout] {e}")
        return JsonResponse(
            {"status": "error", "message": str(e)},
            status=500,
        )


# -----------------------------------------------------------------------------
# PROTECTED: WORKSPACES
# -----------------------------------------------------------------------------


# from django.http import JsonResponse
# from django.views.decorators.csrf import csrf_exempt
# from django.views.decorators.http import require_http_methods
@csrf_exempt
@require_access_token
def workspaces(request):
    user_email = request.user_email
    is_admin = request.is_admin

    # =========================
    # GET: LIST WORKSPACES
    # =========================
    if request.method == "GET":

        # 🔑 ADMIN → ALL WORKSPACES
        if is_admin:
            rows = run_query(
                """
                SELECT
                    w.id,
                    w.name,
                    w.description,
                    w.created_by,
                    w.created_at,
                    'owner' AS role,
                    COUNT(DISTINCT wm.user_email) AS member_count
                FROM workspaces w
                LEFT JOIN workspace_members wm
                  ON wm.workspace_id = w.id
                GROUP BY w.id
                ORDER BY w.created_at DESC
                """,
                fetchall=True,
            )

        # 👤 MEMBER / LEADER → ONLY JOINED WORKSPACES
        else:
            rows = run_query(
                """
                SELECT
                    w.id,
                    w.name,
                    w.description,
                    w.created_by,
                    w.created_at,
                    m.role,
                    COUNT(DISTINCT wm.user_email) AS member_count
                FROM workspaces w
                JOIN workspace_members m
                  ON m.workspace_id = w.id
                LEFT JOIN workspace_members wm
                  ON wm.workspace_id = w.id
                WHERE m.user_email = %s
                GROUP BY w.id, m.role
                ORDER BY w.created_at DESC
                """,
                (user_email,),
                fetchall=True,
            )

        return JsonResponse(rows, safe=False, status=200)

    # =========================
    # POST: CREATE WORKSPACE
    # =========================
    if request.method == "POST":

        if not _can_create_workspace(user_email):
            return JsonResponse(
                {"message": "Not allowed to create workspace"},
                status=403,
            )

        data = get_request_data(request)
        name = data.get("name")
        description = data.get("description", "")

        if not name:
            return JsonResponse(
                {"message": "Workspace name required"},
                status=400,
            )

        run_query(
            """
            INSERT INTO workspaces (name, description, created_by)
            VALUES (%s, %s, %s)
            """,
            (name, description, user_email),
        )

        ws_id = get_last_insert_id()

        run_query(
            """
            INSERT INTO workspace_members (workspace_id, user_email, role)
            VALUES (%s, %s, 'member')
            """,
            (ws_id, user_email),
        )

        return JsonResponse(
            {
                "id": ws_id,
                "name": name,
                "description": description,
                "member_count": 1,
                "role": "member",
            },
            status=201,
        )

    return JsonResponse({"message": "Method not allowed"}, status=405)


@csrf_exempt
@require_access_token
def assign_workspace_leader(request):
    actor = get_current_user(request)
    data = get_request_data(request)

    ws_id = data.get("workspace_id")
    email = data.get("email")

    if not can_assign_leader(actor, ws_id):
        logger.warning(f"[SECURITY] {actor} denied leader assign in ws {ws_id}")
        return JsonResponse({"status": "error"}, status=403)

    logger.info(f"[WORKSPACE] {actor} assigned leader {email} in ws {ws_id}")

    run_query(
        """
        UPDATE workspace_members
        SET role = 'leader'
        WHERE workspace_id = %s AND user_email = %s
        """,
        (ws_id, email),
    )

    return JsonResponse({"status": "success"})


@csrf_exempt
@require_access_token
def workspace_members_view(request, workspace_id):
    user_email = request.user_email
    is_admin = request.is_admin

    role = None

    # --------------------------------------------------
    # STEP 1: Resolve membership
    # --------------------------------------------------
    if not is_admin:
        row = run_query(
            """
            SELECT role
            FROM workspace_members
            WHERE workspace_id = %s AND user_email = %s
            """,
            (workspace_id, user_email),
            fetchone=True,
        )

        if not row:
            return JsonResponse({"message": "Forbidden"}, status=403)

        role = row["role"]

    # ==================================================
    # GET → LIST MEMBERS
    # ==================================================
    if request.method == "GET":
        rows = run_query(
            """
            SELECT
                wm.user_email,
                u.full_name,
                u.username,
                wm.role,
                wm.added_at
            FROM workspace_members wm
            LEFT JOIN users u ON u.email = wm.user_email
            WHERE wm.workspace_id = %s
            ORDER BY wm.added_at ASC
            """,
            (workspace_id,),
            fetchall=True,
        )
        return JsonResponse(rows, safe=False)

    # --------------------------------------------------
    # Only admin or leader beyond this point
    # --------------------------------------------------
    if not is_admin and role != "leader":
        return JsonResponse({"message": "Forbidden"}, status=403)

    data = get_request_data(request)
    target_email = data.get("user_email")

    # ==================================================
    # POST → ADD MEMBER
    # ==================================================
    if request.method == "POST":
        if not target_email:
            return JsonResponse({"message": "user_email required"}, status=400)

        run_query(
            """
            INSERT IGNORE INTO workspace_members (workspace_id, user_email, role)
            VALUES (%s, %s, 'member')
            """,
            (workspace_id, target_email),
        )

        # 🔔 Notify Admins + Leaders
        admins = run_query(
            """
            SELECT user_email
            FROM workspace_members
            WHERE workspace_id = %s AND role IN ('admin', 'leader')
            """,
            (workspace_id,),
            fetchall=True,
        )

        for admin in admins or []:
            admin_email = admin["user_email"]

            if admin_email == user_email:
                continue

            notif_id = run_query(
                """
                INSERT INTO notifications (user_email, type, payload)
                VALUES (%s, %s, %s)
                """,
                (
                    admin_email,
                    "workspace_member_joined",
                    json.dumps(
                        {
                            "title": "New Member Joined",
                            "message": f"{target_email} joined workspace",
                        }
                    ),
                ),
                return_last_id=True,
            )

            broadcast_notification(
                admin_email,
                {
                    "event": "notification",
                    "id": notif_id,
                    "type": "workspace_member_joined",
                    "payload": {
                        "title": "New Member Joined",
                        "message": f"{target_email} joined workspace",
                    },
                    "created_at": datetime.datetime.utcnow().isoformat() + "Z",
                },
            )

        return JsonResponse(
            {"status": "success", "message": "Member added"},
            status=201,
        )

    # ==================================================
    # DELETE → REMOVE MEMBER
    # ==================================================
    if request.method == "DELETE":
        if not target_email:
            return JsonResponse({"message": "user_email required"}, status=400)

        target_role = run_query(
            """
            SELECT role
            FROM workspace_members
            WHERE workspace_id = %s AND user_email = %s
            """,
            (workspace_id, target_email),
            fetchone=True,
        )

        if target_role and target_role["role"] == "leader" and not is_admin:
            return JsonResponse({"message": "Leader cannot be removed"}, status=403)

        run_query(
            """
            DELETE FROM workspace_members
            WHERE workspace_id = %s AND user_email = %s
            """,
            (workspace_id, target_email),
        )

        # 🔔 Notify Admins + Leaders
        admins = run_query(
            """
            SELECT user_email
            FROM workspace_members
            WHERE workspace_id = %s AND role IN ('admin', 'leader')
            """,
            (workspace_id,),
            fetchall=True,
        )

        for admin in admins or []:
            admin_email = admin["user_email"]

            if admin_email == user_email:
                continue

            notif_id = run_query(
                """
                INSERT INTO notifications (user_email, type, payload)
                VALUES (%s, %s, %s)
                """,
                (
                    admin_email,
                    "workspace_member_removed",
                    json.dumps(
                        {
                            "title": "Member Removed",
                            "message": f"{target_email} was removed",
                        }
                    ),
                ),
                return_last_id=True,
            )

            broadcast_notification(
                admin_email,
                {
                    "event": "notification",
                    "id": notif_id,
                    "type": "workspace_member_removed",
                    "payload": {
                        "title": "Member Removed",
                        "message": f"{target_email} was removed",
                    },
                    "created_at": datetime.datetime.utcnow().isoformat() + "Z",
                },
            )

        return JsonResponse({"status": "success", "message": "Member removed"})

    return JsonResponse({"message": "Method not allowed"}, status=405)


@csrf_exempt
@require_access_token
def channel_members_view(request, channel_id):
    user_email = request.user_email
    is_admin = request.is_admin

    # =========================
    # Resolve workspace_id
    # =========================
    row = run_query(
        """
        SELECT workspace_id
        FROM channels
        WHERE id = %s
        """,
        (channel_id,),
        fetchone=True,
    )

    if not row:
        return JsonResponse({"message": "Channel not found"}, status=404)

    workspace_id = row["workspace_id"]

    # =========================
    # Check workspace membership
    # =========================
    role = None
    if not is_admin:
        r = run_query(
            """
            SELECT role
            FROM workspace_members
            WHERE workspace_id = %s AND user_email = %s
            """,
            (workspace_id, user_email),
            fetchone=True,
        )
        role = r["role"] if r else None

        # ❗ must be a workspace member at least
        if role not in ("leader", "member"):
            return JsonResponse({"message": "Forbidden"}, status=403)

    # =========================
    # GET: LIST CHANNEL MEMBERS
    # (Admins + Leaders + Members)
    # =========================
    if request.method == "GET":
        rows = run_query(
            """
            SELECT
                cm.user_email,
                u.full_name,
                cm.added_at
            FROM channel_members cm
            LEFT JOIN users u ON u.email = cm.user_email
            WHERE cm.channel_id = %s
            ORDER BY cm.added_at ASC
            """,
            (channel_id,),
            fetchall=True,
        )
        return JsonResponse(rows, safe=False)

    data = get_request_data(request)
    target_email = data.get("user_email")

    # =========================
    # POST: ADD MEMBER
    # (Admins / Leaders only)
    # =========================
    if request.method == "POST":

        if not (is_admin or role == "leader"):
            return JsonResponse({"message": "Forbidden"}, status=403)

        if not target_email:
            return JsonResponse(
                {"message": "user_email required"},
                status=400,
            )

        run_query(
            """
            INSERT IGNORE INTO channel_members (channel_id, user_email)
            VALUES (%s, %s)
            """,
            (channel_id, target_email),
        )

        return JsonResponse(
            {"status": "success", "message": "Member added"},
            status=201,
        )

    # =========================
    # DELETE: REMOVE MEMBER
    # (Admins / Leaders only)
    # =========================
    if request.method == "DELETE":

        if not (is_admin or role == "leader"):
            return JsonResponse({"message": "Forbidden"}, status=403)

        if not target_email:
            return JsonResponse(
                {"message": "user_email required"},
                status=400,
            )

        run_query(
            """
            DELETE FROM channel_members
            WHERE channel_id = %s AND user_email = %s
            """,
            (channel_id, target_email),
        )

        return JsonResponse({"status": "success", "message": "Member removed"})

    return JsonResponse({"message": "Method not allowed"}, status=405)


# -----------------------------------------------------------------------------
# PROTECTED: CHANNELS
@csrf_exempt
@require_access_token
def channels_view(request, workspace_id):
    user_email = request.user_email
    is_admin = request.is_admin

    # =========================
    # Validate workspace membership
    # =========================
    role = None
    if not is_admin:
        row = run_query(
            """
            SELECT role
            FROM workspace_members
            WHERE workspace_id = %s AND user_email = %s
            """,
            (workspace_id, user_email),
            fetchone=True,
        )
        role = row["role"] if row else None

        if role not in ("leader", "member"):
            return JsonResponse({"message": "Forbidden"}, status=403)

    # =========================
    # GET: LIST CHANNELS (ALL MEMBERS)
    # =========================
    if request.method == "GET":
        rows = run_query(
            """
            SELECT id, name, created_by, created_at
            FROM channels
            WHERE workspace_id = %s
            ORDER BY created_at ASC
            """,
            (workspace_id,),
            fetchall=True,
        )

        return JsonResponse(rows, safe=False)

    # =========================
    # POST: CREATE CHANNEL (LEADER / ADMIN)
    # =========================
    if request.method == "POST":
        if not (is_admin or role == "leader"):
            return JsonResponse({"message": "Forbidden"}, status=403)

        data = get_request_data(request)
        name = (data.get("name") or "").strip()

        if not name:
            return JsonResponse(
                {"message": "Channel name required"},
                status=400,
            )

        run_query(
            """
            INSERT INTO channels (workspace_id, name, created_by)
            VALUES (%s, %s, %s)
            """,
            (workspace_id, name, user_email),
        )

        channel_id = get_last_insert_id()

        # Auto-add creator
        run_query(
            """
            INSERT INTO channel_members (channel_id, user_email)
            VALUES (%s, %s)
            """,
            (channel_id, user_email),
        )

        return JsonResponse(
            {
                "status": "success",
                "channel_id": channel_id,
                "name": name,
            },
            status=201,
        )

    # =========================
    # DELETE: DELETE CHANNEL (LEADER / ADMIN)
    # =========================
    if request.method == "DELETE":
        if not (is_admin or role == "leader"):
            return JsonResponse({"message": "Forbidden"}, status=403)

        data = get_request_data(request)
        channel_id = data.get("channel_id")

        if not channel_id:
            return JsonResponse(
                {"message": "channel_id required"},
                status=400,
            )

        run_query(
            "DELETE FROM channels WHERE id = %s AND workspace_id = %s",
            (channel_id, workspace_id),
        )
        run_query(
            "DELETE FROM channel_members WHERE channel_id = %s",
            (channel_id,),
        )

        return JsonResponse({"status": "success", "message": "Channel deleted"})

    return JsonResponse({"message": "Method not allowed"}, status=405)


@csrf_exempt
@require_access_token
def messages(request):
    user = getattr(request, "user_username", None)

    # Helper: get workspace_id for a channel
    def _get_channel_workspace_id(channel_id):
        row = run_query(
            "SELECT workspace_id FROM channels WHERE id = %s",
            (channel_id,),
            fetchone=True,
        )
        if not row:
            return None
        # handle dict or tuple
        return row["workspace_id"] if isinstance(row, dict) else row[0]

    # ------------------------------------------------------------------
    # GET: list messages for a channel (only if user is member of workspace)
    # ------------------------------------------------------------------
    if request.method == "GET":
        channel_id = request.GET.get("channel_id")
        if not channel_id:
            return JsonResponse(
                {"status": "error", "message": "channel_id required"},
                status=400,
            )

        ws_id = _get_channel_workspace_id(channel_id)
        if not ws_id:
            return JsonResponse(
                {"status": "error", "message": "Channel not found"},
                status=404,
            )

        # Permission: admin or member of that workspace
        if not _is_admin(user) and not _is_workspace_member(user, ws_id):
            return JsonResponse(
                {"status": "error", "message": "Forbidden"},
                status=403,
            )

        rows = run_query(
            """
            SELECT id, sender_email, body, created_at
            FROM messages
            WHERE channel_id = %s
            ORDER BY created_at ASC
            """,
            (channel_id,),
            fetchall=True,
        )

        return JsonResponse({"status": "success", "data": rows})

    # ------------------------------------------------------------------
    # POST: send a message (and trigger mentions / task tags)
    # ------------------------------------------------------------------
    elif request.method == "POST":
        data = get_request_data(request)
        channel_id = data.get("channel_id")
        body = (data.get("body") or "").strip()

        if not channel_id or not body:
            return JsonResponse(
                {"status": "error", "message": "Missing fields"},
                status=400,
            )

        ws_id = _get_channel_workspace_id(channel_id)
        if not ws_id:
            return JsonResponse(
                {"status": "error", "message": "Channel not found"},
                status=404,
            )

        # Permission: admin or member of that workspace
        if not _is_admin(user) and not _is_workspace_member(user, ws_id):
            return JsonResponse(
                {"status": "error", "message": "Forbidden"},
                status=403,
            )

        # Save message
        run_query(
            """
            INSERT INTO messages (channel_id, sender_email, body)
            VALUES (%s, %s, %s)
            """,
            (channel_id, user, body),
        )
        msg_id = get_last_insert_id()

        # 🔁 NEW: process @mentions and #task123 tags
        # This will create notifications + optional emails
        try:
            _process_message_mentions(channel_id, msg_id, body, user)
        except Exception as e:
            # Don't break chat if notifications fail
            logger.exception(f"[Messages] Failed to process mentions: {e}")

        return JsonResponse({"status": "success", "message_id": msg_id}, status=201)

    # ------------------------------------------------------------------
    # Unsupported methods
    # ------------------------------------------------------------------
    else:
        return JsonResponse(
            {"status": "error", "message": "Method not allowed"},
            status=405,
        )


# PROTECTED: ACTIVITIES
# -----------------------------------------------------------------------------


@csrf_exempt
@require_access_token
def activities(request):
    user = getattr(request, "user_username", None)

    if request.method != "POST":
        return JsonResponse({"status": "error", "message": "POST required"}, status=405)

    data = get_request_data(request)
    ws_id = data.get("workspace_id")
    limit = int(data.get("limit", 20))

    if not ws_id:
        return JsonResponse(
            {"status": "error", "message": "workspace_id required"}, status=400
        )

    rows = run_query(
        """
        SELECT id, actor_email, type, ref_id, summary, created_at
        FROM activities
        WHERE workspace_id=%s
        ORDER BY id DESC
        LIMIT %s
        """,
        (ws_id, limit),
        fetchall=True,
    )
    return JsonResponse({"status": "success", "data": rows})


# -----------------------------------------------------------------------------
# PROTECTED: METRICS
# -----------------------------------------------------------------------------


@csrf_exempt
@require_access_token
def metrics_messages_per_day(request):
    user = getattr(request, "user_username", None)

    if request.method != "POST":
        return JsonResponse({"status": "error", "message": "POST required"}, status=405)

    data = get_request_data(request)
    ws_id = data.get("workspace_id")

    if not ws_id:
        return JsonResponse(
            {"status": "error", "message": "workspace_id required"}, status=400
        )

    # ✅ permission check: only workspace members or admins can see metrics
    if not _is_admin(user):
        role = _get_workspace_role(user, ws_id)
        if not role:
            return JsonResponse({"status": "error", "message": "Forbidden"}, status=403)

    rows = run_query(
        """
        SELECT DATE(m.created_at) AS day, COUNT(*) AS count
        FROM messages m
        JOIN channels c ON c.id = m.channel_id
        WHERE c.workspace_id=%s
          AND m.created_at >= DATE_SUB(CURDATE(), INTERVAL 13 DAY)
        GROUP BY day
        ORDER BY day ASC
        """,
        (ws_id,),
        fetchall=True,
    )
    return JsonResponse({"status": "success", "data": rows})


@csrf_exempt
@require_access_token
def metrics_active_users(request):
    user = getattr(request, "user_username", None)

    if request.method != "POST":
        return JsonResponse({"status": "error", "message": "POST required"}, status=405)

    data = get_request_data(request)
    ws_id = data.get("workspace_id")
    minutes = int(data.get("minutes", 15))

    if not ws_id:
        return JsonResponse(
            {"status": "error", "message": "workspace_id required"}, status=400
        )

    # ✅ permission check: only workspace members or admins can see metrics
    if not _is_admin(user):
        role = _get_workspace_role(user, ws_id)
        if not role:
            return JsonResponse({"status": "error", "message": "Forbidden"}, status=403)

    row = run_query(
        """
        SELECT COUNT(*) AS active_count
        FROM workspace_members m
        JOIN presence p ON p.user_email = m.user_email
        WHERE m.workspace_id=%s
          AND p.last_seen >= DATE_SUB(NOW(), INTERVAL %s MINUTE)
          AND p.status IN ('online', 'idle')
        """,
        (ws_id, minutes),
        fetchone=True,
    )
    return JsonResponse({"status": "success", "data": row or {"active_count": 0}})


@csrf_exempt
def refresh_endpoint(request):
    rt = request.COOKIES.get("refresh_token")
    if not rt:
        return JsonResponse(
            {"status": "error", "message": "No refresh token"}, status=401
        )

    try:
        payload = decode_token(rt)
        username = payload["sub"]
        exp = payload["exp"]
        jti = payload["jti"]

        if is_refresh_revoked(jti):
            return JsonResponse(
                {"status": "error", "message": "Token revoked"}, status=403
            )

        access_token = create_access_token(username)
        id_token = create_id_token(username, username, username)

        response = JsonResponse({"status": "success", "user": {"email": username}})
        response.set_cookie("access_token", access_token, max_age=600, **COOKIE_KWARGS)
        response.set_cookie("id_token", id_token, max_age=600, **COOKIE_KWARGS)

        return response

    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=401)


@csrf_exempt
@require_access_token
def workspace_members(request):
    """
    GET    /api/workspace-members/?workspace_id=1
    POST   /api/workspace-members/          (add member)
    PATCH  /api/workspace-members/          (change role)
    DELETE /api/workspace-members/          (remove member)

    Admin: full access to all workspaces
    Owner: full access for their own workspace
    Member: can only GET (optional), no write
    """
    current_user = _get_current_user_email(request)

    # -------- GET: list members of a workspace --------
    if request.method == "GET":
        workspace_id = request.GET.get("workspace_id")
        if not workspace_id:
            return JsonResponse(
                {"status": "error", "message": "workspace_id required"}, status=400
            )

        # Admin can view any workspace
        if not _is_admin(current_user):
            role = _get_workspace_role(current_user, workspace_id)
            if not role:
                return JsonResponse(
                    {"status": "error", "message": "Forbidden"}, status=403
                )

        rows = run_query(
            """
            SELECT
                m.workspace_id,
                m.user_email,
                m.role,
                u.full_name,
                u.username
            FROM workspace_members m
            LEFT JOIN users u ON u.email = m.user_email
            WHERE m.workspace_id = %s
            ORDER BY 
                CASE WHEN m.role = 'owner' THEN 0 ELSE 1 END,
                u.full_name
            """,
            (workspace_id,),
            fetchall=True,
        )

        return JsonResponse({"status": "success", "data": rows})

    # For write operations we require admin OR owner of that workspace
    data = get_request_data(request)
    workspace_id = data.get("workspace_id")

    if not workspace_id:
        return JsonResponse(
            {"status": "error", "message": "workspace_id required"}, status=400
        )

    if not (_is_admin(current_user) or _is_workspace_owner(current_user, workspace_id)):
        return JsonResponse({"status": "error", "message": "Forbidden"}, status=403)

    # -------- POST: add member --------
    if request.method == "POST":
        target_email = (data.get("user_email") or "").strip().lower()
        role = (data.get("role") or "member").strip().lower()

        if not target_email:
            return JsonResponse(
                {"status": "error", "message": "user_email required"}, status=400
            )

        if role not in ("owner", "member"):
            return JsonResponse(
                {"status": "error", "message": "Invalid role"}, status=400
            )

        # Check if already member
        existing = run_query(
            """
            SELECT 1 FROM workspace_members
            WHERE workspace_id = %s AND user_email = %s
            """,
            (workspace_id, target_email),
            fetchone=True,
        )
        if existing:
            return JsonResponse(
                {"status": "error", "message": "User already a member"}, status=400
            )

        run_query(
            """
            INSERT INTO workspace_members (workspace_id, user_email, role)
            VALUES (%s, %s, %s)
            """,
            (workspace_id, target_email, role),
        )

        return JsonResponse({"status": "success", "message": "Member added"})

    # -------- PATCH: change role --------
    if request.method == "PATCH":
        target_email = (data.get("user_email") or "").strip().lower()
        new_role = (data.get("role") or "").strip().lower()

        if not target_email or not new_role:
            return JsonResponse(
                {"status": "error", "message": "user_email and role required"},
                status=400,
            )

        if new_role not in ("owner", "member"):
            return JsonResponse(
                {"status": "error", "message": "Invalid role"}, status=400
            )

        run_query(
            """
            UPDATE workspace_members
            SET role = %s
            WHERE workspace_id = %s AND user_email = %s
            """,
            (new_role, workspace_id, target_email),
        )

        return JsonResponse({"status": "success", "message": "Role updated"})

    # -------- DELETE: remove member --------
    if request.method == "DELETE":
        target_email = (data.get("user_email") or "").strip().lower()
        if not target_email:
            return JsonResponse(
                {"status": "error", "message": "user_email required"}, status=400
            )

        # Optional: prevent removing last owner, you can add that rule later
        run_query(
            """
            DELETE FROM workspace_members
            WHERE workspace_id = %s AND user_email = %s
            """,
            (workspace_id, target_email),
        )

        return JsonResponse({"status": "success", "message": "Member removed"})

    return JsonResponse(
        {"status": "error", "message": "Method not allowed"}, status=405
    )


@csrf_exempt
@require_access_token
def workspace_info(request):
    if request.method != "GET":
        return JsonResponse({"status": "error", "message": "GET required"}, status=405)

    ws_id = request.GET.get("workspace_id")
    if not ws_id:
        return JsonResponse(
            {"status": "error", "message": "workspace_id required"}, status=400
        )

    row = run_query(
        """
        SELECT id, name, description, created_by, created_at
        FROM workspaces
        WHERE id=%s
        """,
        (ws_id,),
        fetchone=True,
    )

    return JsonResponse({"status": "success", "data": row})


@csrf_exempt
@require_access_token
def task_create(request):
    user = request.user_username

    if request.method != "POST":
        return JsonResponse({"message": "POST required"}, status=405)

    data = get_request_data(request)
    ws_id = data.get("workspace_id")
    title = data.get("title")
    assignee = data.get("assignee_email")

    if not ws_id or not title:
        return JsonResponse({"message": "workspace_id and title required"}, status=400)

    if not _is_admin(user) and not _is_workspace_member(user, ws_id):
        return JsonResponse({"message": "Forbidden"}, status=403)

    task_id = run_query(
        """
        INSERT INTO tasks
        (workspace_id, created_by, title, description, priority, assignee_email)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (
            ws_id,
            user,
            title,
            data.get("description", ""),
            data.get("priority", "normal"),
            assignee,
        ),
        return_last_id=True,
    )

    # Notify assignee (only if not self)
    if assignee and assignee != user:
        notif_id = run_query(
            """
            INSERT INTO notifications (user_email, type, payload)
            VALUES (%s, %s, %s)
            """,
            (
                assignee,
                "task_assigned",
                json.dumps(
                    {
                        "task_id": task_id,
                        "title": title,
                        "message": "You were assigned this task",
                        "assigned_by": user,
                    }
                ),
            ),
            return_last_id=True,
        )

        broadcast_notification(
            assignee,
            {
                "event": "notification",
                "id": notif_id,
                "type": "task_assigned",
                "payload": {
                    "title": title,
                    "message": "You were assigned this task",
                },
                "created_at": datetime.datetime.utcnow().isoformat() + "Z",
            },
        )

    return JsonResponse({"status": "success", "task_id": task_id}, status=201)


@csrf_exempt
@require_access_token
def task_update(request):
    user = request.user_username
    data = get_request_data(request)
    task_id = data.get("task_id")

    if not task_id:
        return JsonResponse({"message": "task_id required"}, status=400)

    task = run_query(
        """
        SELECT id, workspace_id, created_by, assignee_email, title
        FROM tasks
        WHERE id = %s
        """,
        (task_id,),
        fetchone=True,
    )

    if not task:
        return JsonResponse({"message": "Task not found"}, status=404)

    ws_id = task["workspace_id"]
    created_by = task["created_by"]
    old_assignee = task["assignee_email"]
    title = task["title"]

    # Permission
    if not _is_admin(user) and user not in [created_by, old_assignee]:
        return JsonResponse({"message": "Forbidden"}, status=403)

    fields, params = [], []
    new_assignee = old_assignee

    # Collect updates
    for field in ["title", "description", "priority", "status", "assignee_email"]:
        if field in data:
            fields.append(f"{field}=%s")
            params.append(data[field])
            if field == "assignee_email":
                new_assignee = data[field]

    if not fields:
        return JsonResponse({"message": "Nothing to update"}, status=400)

    params.append(task_id)
    run_query(f"UPDATE tasks SET {', '.join(fields)} WHERE id=%s", params)

    # ----------------------------
    # Activity feed (workspace-wide)
    # ----------------------------
    _insert_activity(
        ws_id,
        user,
        "task_updated",
        task_id,
        f"{user} updated task: {title}",
    )

    _broadcast_activity(
        ws_id,
        {
            "type": "task_updated",
            "actor": user,
            "ref_id": task_id,
            "summary": f"{user} updated task: {title}",
        },
    )

    # ----------------------------
    # 🔔 NOTIFICATION LOGIC (FIXED)
    # ----------------------------

    # CASE 1: assignee changed → notify new assignee
    if new_assignee and new_assignee != old_assignee and new_assignee != user:
        run_query(
            "INSERT INTO notifications (user_email, type, payload) VALUES (%s, %s, %s)",
            (
                new_assignee,
                "task_assigned",
                json.dumps(
                    {
                        "task_id": task_id,
                        "title": title,
                        "message": "You were assigned this task",
                        "assigned_by": user,
                    }
                ),
            ),
        )

        broadcast_notification(
            new_assignee,
            {
                "event": "notification",
                "type": "task_assigned",
                "payload": {
                    "title": title,
                    "message": "You were assigned this task",
                },
                "created_at": datetime.datetime.utcnow().isoformat() + "Z",
            },
        )

    # CASE 2: task updated (same assignee) → notify assignee
    # CASE 3: task marked completed → notify creator
    if data.get("status") == "completed" and created_by != user:
        notif_id = run_query(
            """
            INSERT INTO notifications (user_email, type, payload)
            VALUES (%s, %s, %s)
            """,
            (
                created_by,
                "task_completed",
                json.dumps(
                    {
                        "task_id": task_id,
                        "title": title,
                        "message": f"{user} completed the task",
                    }
                ),
            ),
            return_last_id=True,
        )

        broadcast_notification(
            created_by,
            {
                "event": "notification",
                "id": notif_id,
                "type": "task_completed",
                "payload": {
                    "title": title,
                    "message": f"{user} completed the task",
                },
                "created_at": datetime.datetime.utcnow().isoformat() + "Z",
            },
        )

    return JsonResponse({"status": "success"})


@csrf_exempt
@require_access_token
def task_delete(request):
    user = request.user_username
    data = get_request_data(request)
    task_id = data.get("task_id")

    if not task_id:
        return JsonResponse({"message": "task_id required"}, status=400)

    task = run_query(
        """
        SELECT id, workspace_id, created_by, assignee_email, title
        FROM tasks
        WHERE id=%s
        """,
        (task_id,),
        fetchone=True,
    )

    if not task:
        return JsonResponse({"message": "Task not found"}, status=404)

    ws_id = task["workspace_id"]
    title = task["title"]

    if not _is_admin(user) and user not in [task["created_by"], task["assignee_email"]]:
        return JsonResponse({"message": "Forbidden"}, status=403)

    run_query("DELETE FROM tasks WHERE id=%s", (task_id,))

    # -----------------------------
    # ACTIVITY FEED
    # -----------------------------
    _insert_activity(
        ws_id,
        user,
        "task_deleted",
        task_id,
        f"{user} deleted task: {title}",
    )

    _broadcast_activity(
        ws_id,
        {
            "type": "task_deleted",
            "actor": user,
            "ref_id": task_id,
            "summary": f"{user} deleted task: {title}",
        },
    )

    return JsonResponse({"status": "success", "deleted": True})


@csrf_exempt
@require_access_token
def tasks(request):
    user = getattr(request, "user_username", None)

    if request.method != "GET":
        return JsonResponse({"status": "error", "message": "GET required"}, status=405)

    # helper for default workspace logic
    def get_default_workspace_id():
        row = run_query(
            """
            SELECT w.id
            FROM workspaces w
            JOIN workspace_members m ON m.workspace_id = w.id
            WHERE m.user_email = %s
            ORDER BY w.created_at DESC
            LIMIT 1
            """,
            (user,),
            fetchone=True,
        )
        # row can be tuple or dict
        if not row:
            return None
        return row["id"] if isinstance(row, dict) else row[0]

    ws_id = request.GET.get("workspace_id")

    if not ws_id:
        ws_id = get_default_workspace_id()

    if not ws_id:
        return JsonResponse(
            {"status": "error", "message": "No workspace available for this user"},
            status=404,
        )

    # ✅ Permission: admin OR workspace member
    if not _is_admin(user) and not _is_workspace_member(user, ws_id):
        return JsonResponse(
            {"status": "error", "message": "Forbidden"},
            status=403,
        )

    rows = run_query(
        """
        SELECT *
        FROM tasks
        WHERE workspace_id = %s
        ORDER BY created_at DESC
        """,
        (ws_id,),
        fetchall=True,
    )

    return JsonResponse({"status": "success", "workspace_id": ws_id, "data": rows})


@csrf_exempt
@require_access_token
def super_admin_update_admin(request):
    actor = get_current_user(request)

    if not is_super_admin(actor):
        logger.warning(f"[SECURITY] Non-super-admin tried admin update: {actor}")
        return JsonResponse({"status": "error"}, status=403)

    data = get_request_data(request)
    target = data.get("email")
    is_admin_flag = data.get("is_admin")

    logger.info(f"[ADMIN] {actor} set admin={is_admin_flag} for {target}")

    run_query(
        "UPDATE users SET is_admin = %s WHERE email = %s",
        (1 if is_admin_flag else 0, target),
    )

    return JsonResponse({"status": "success"})


@csrf_exempt
@require_access_token
def admin_create_workspace(request):
    actor = get_current_user(request)

    if not _is_admin(actor):
        logger.warning(f"[SECURITY] Non-admin tried workspace create: {actor}")
        return JsonResponse({"status": "error", "message": "Forbidden"}, status=403)

    data = get_request_data(request)
    name = data.get("name")
    description = data.get("description", "")

    if not name:
        return JsonResponse(
            {"status": "error", "message": "Workspace name is required"}, status=400
        )

    logger.info(f"[WORKSPACE] {actor} creating workspace: {name}")

    try:
        # 1️⃣ Insert workspace
        run_query(
            """
            INSERT INTO workspaces (name, description, created_by)
            VALUES (%s, %s, %s)
            """,
            (name, description, actor),
        )

        # 2️⃣ Get workspace id SAFELY (works with your helper)
        row = run_query(
            """
            SELECT id FROM workspaces
            WHERE name = %s AND created_by = %s
            ORDER BY id DESC
            LIMIT 1
            """,
            (name, actor),
            fetchone=True,
        )

        if not row:
            logger.error("[WORKSPACE] Workspace insert succeeded but ID fetch failed")
            return JsonResponse(
                {"status": "error", "message": "Workspace creation failed"}, status=500
            )

        # handle tuple OR dict
        ws_id = list(row.values())[0] if isinstance(row, dict) else row[0]

        # 3️⃣ Insert owner membership (avoid crash if retried)
        run_query(
            """
            INSERT IGNORE INTO workspace_members (workspace_id, user_email, role)
            VALUES (%s, %s, 'owner')
            """,
            (ws_id, actor),
        )

        logger.info(f"[WORKSPACE] Workspace {ws_id} created by {actor}")

        return JsonResponse({"status": "success", "workspace_id": ws_id})

    except Exception as e:
        logger.exception(
            f"[WORKSPACE] Unexpected error while creating workspace by {actor}"
        )
        return JsonResponse(
            {
                "status": "error",
                "message": "Something went wrong while creating workspace",
            },
            status=500,
        )


@csrf_exempt
@require_access_token
def manage_workspace_member(request):
    actor = get_current_user(request)
    data = get_request_data(request)

    ws_id = data.get("workspace_id")
    email = data.get("email")
    action = data.get("action")  # add | remove

    if not can_manage_workspace(actor, ws_id):
        logger.warning(f"[SECURITY] {actor} denied member {action} on ws {ws_id}")
        return JsonResponse({"status": "error"}, status=403)

    logger.info(f"[WORKSPACE] {actor} {action} member {email} in ws {ws_id}")

    if action == "add":
        run_query(
            """
            INSERT IGNORE INTO workspace_members
            (workspace_id, user_email, role)
            VALUES (%s, %s, 'member')
            """,
            (ws_id, email),
        )
    else:
        run_query(
            """
            DELETE FROM workspace_members
            WHERE workspace_id = %s AND user_email = %s
            """,
            (ws_id, email),
        )

    return JsonResponse({"status": "success"})


@csrf_exempt
@require_access_token
def account(request):
    user_email = get_current_user(request)

    logger.info(f"[ACCOUNT] Fetch account for {user_email}")

    row = run_query(
        """
        SELECT email, username, full_name,
               is_admin, is_super_admin, is_active
        FROM users WHERE email = %s
        """,
        (user_email,),
        fetchone=True,
    )

    if not row:
        logger.warning(f"[ACCOUNT] User not found: {user_email}")
        return JsonResponse({"status": "error"}, status=404)

    if not row["is_active"]:
        logger.warning(f"[ACCOUNT] Inactive user blocked: {user_email}")
        return JsonResponse(
            {"status": "error", "message": "Account disabled"}, status=403
        )

    return JsonResponse({"status": "success", "data": row})


# @csrf_exempt
# @require_access_token
# def github_integrations(request):
#     user = getattr(request, "user_username", None)

#     # ------------------ LIST ------------------
#     if request.method == "GET":
#         ws_id = request.GET.get("workspace_id")
#         if not ws_id:
#             return JsonResponse(
#                 {"status": "error", "message": "workspace_id required"},
#                 status=400,
#             )

#         # permission: admin or member of workspace
#         if not _is_admin(user):
#             role = _get_workspace_role(user, ws_id)
#             if not role:
#                 return JsonResponse(
#                     {"status": "error", "message": "Forbidden"},
#                     status=403,
#                 )

#         rows = run_query(
#             """
#             SELECT
#                 id,
#                 workspace_id,
#                 repo_full_name,
#                 events_mask,
#                 is_active,
#                 created_at
#             FROM github_repos
#             WHERE workspace_id = %s
#             ORDER BY created_at DESC
#             """,
#             (ws_id,),
#             fetchall=True,
#         )

#         return JsonResponse({"status": "success", "data": rows})
#     # ------------------ CREATE ------------------
#     if request.method == "POST":
#         data = get_request_data(request)
#         ws_id = data.get("workspace_id")
#         repo_full_name = (data.get("repo_full_name") or "").strip()
#         events_mask = (data.get("events_mask") or "push,pr,issues").strip()

#         if not ws_id or not repo_full_name:
#             return JsonResponse(
#                 {
#                     "status": "error",
#                     "message": "workspace_id and repo_full_name required",
#                 },
#                 status=400,
#             )

#         # permission: admin or owner of workspace
#         if not _is_admin(user):
#             role = _get_workspace_role(user, ws_id)
#             if role != "owner":
#                 return JsonResponse(
#                     {
#                         "status": "error",
#                         "message": "Only owner or admin can configure GitHub",
#                     },
#                     status=403,
#                 )

#         # generate a new webhook secret
#         webhook_secret = secrets.token_hex(32)

#         try:
#             run_query(
#                 """
#                 INSERT INTO github_repos (
#                     workspace_id,
#                     repo_full_name,
#                     events_mask,
#                     webhook_secret,
#                     is_active
#                 ) VALUES (%s, %s, %s, %s, 1)
#                 """,
#                 (ws_id, repo_full_name, events_mask, webhook_secret),
#             )
#         except Exception as e:
#             logger.exception(f"[GitHub Integration] Insert error: {e}")
#             return JsonResponse(
#                 {"status": "error", "message": "Failed to create integration"},
#                 status=500,
#             )

#         # return info but do NOT expose secret in normal responses
#         return JsonResponse(
#             {
#                 "status": "success",
#                 "message": "GitHub integration created",
#                 "data": {
#                     "workspace_id": ws_id,
#                     "repo_full_name": repo_full_name,
#                     "events_mask": events_mask,
#                 },
#             },
#             status=201,
#         )
#     # ------------------ DELETE / DISABLE ------------------
#     if request.method == "DELETE":
#         data = get_request_data(request)
#         integ_id = data.get("id")
#         ws_id = data.get("workspace_id")

#         if not integ_id or not ws_id:
#             return JsonResponse(
#                 {"status": "error", "message": "id and workspace_id required"},
#                 status=400,
#             )

#         # permission: admin or owner
#         if not _is_admin(user):
#             role = _get_workspace_role(user, ws_id)
#             if role != "owner":
#                 return JsonResponse(
#                     {
#                         "status": "error",
#                         "message": "Only owner or admin can modify GitHub integrations",
#                     },
#                     status=403,
#                 )

#         run_query(
#             "DELETE FROM github_repos WHERE id = %s AND workspace_id = %s",
#             (integ_id, ws_id),
#         )

#         return JsonResponse({"status": "success", "message": "Integration removed"})

#     return JsonResponse(
#         {"status": "error", "message": "Method not allowed"},
#         status=405,
#     )


@csrf_exempt
def github_webhook(request):

    # -------------------------------
    # 1️⃣ Only allow POST
    # -------------------------------
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    body = request.body

    # -------------------------------
    # 2️⃣ Ignore empty / non-GitHub calls
    # -------------------------------
    event = request.META.get("HTTP_X_GITHUB_EVENT")
    delivery_id = request.META.get("HTTP_X_GITHUB_DELIVERY")
    signature_header = request.META.get("HTTP_X_HUB_SIGNATURE_256")

    if not body or not event or not delivery_id:
        print(
            f"⚠️ Ignored: Not a valid GitHub webhook call. event={event}, delivery_id={delivery_id}, body_len={len(body) if body else 0}"
        )
        return JsonResponse({"status": "ignored", "reason": "missing_headers_or_body"})

    print("\n==============================")
    print("📩 GitHub Webhook Received")
    print(f"Event: {event}")
    print(f"Delivery ID: {delivery_id}")
    print(f"Signature: {signature_header}")
    print("==============================")

    # -------------------------------
    # 3️⃣ Handle ping
    # -------------------------------
    if event == "ping":
        return JsonResponse({"status": "pong"})

    # -------------------------------
    # 4️⃣ Parse JSON
    # -------------------------------
    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception as e:
        print("❌ JSON parse error:", str(e))
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    # -------------------------------
    # 5️⃣ Extract repository
    # -------------------------------
    repository = payload.get("repository")
    if not repository:
        print(
            f"⚠️ Ignored: No repository object in payload. payload_keys={list(payload.keys())}"
        )
        return JsonResponse({"status": "ignored", "reason": "no_repository_object"})

    repo_full_name = repository.get("full_name")
    if not repo_full_name:
        print(
            f"⚠️ Ignored: repository.full_name missing. repo_keys={list(repository.keys())}"
        )
        return JsonResponse(
            {"status": "ignored", "reason": "repository_full_name_missing"}
        )

    print(f"🔍 Repository Identifed: {repo_full_name}")

    # -------------------------------
    # 6️⃣ Load repo integration
    # -------------------------------
    integrations = run_query(
        """
        SELECT workspace_id, webhook_secret, events_mask
        FROM github_repos
        WHERE repo_full_name=%s AND is_active=1
        """,
        (repo_full_name,),
        fetchall=True,
    )

    if not integrations:
        print(f"⚠️ Ignored: Repo '{repo_full_name}' not connected in DB")
        return JsonResponse({"status": "ignored", "reason": "repo_not_connected"})

    # -------------------------------
    # 7️⃣ Validate Signature
    # -------------------------------
    if not signature_header or not signature_header.startswith("sha256="):
        print("❌ Missing signature header")
        return JsonResponse({"error": "Unauthorized"}, status=403)

    received_signature = signature_header.split("=")[1]
    valid_integrations = []

    for row in integrations:
        secret = row["webhook_secret"] or settings.GITHUB_WEBHOOK_SECRET
        computed = hmac.new(
            secret.encode(), msg=body, digestmod=hashlib.sha256
        ).hexdigest()

        if hmac.compare_digest(received_signature, computed):
            # Normalizing events_mask (e.g., 'pr' -> 'pull_request')
            mask_raw = [
                e.strip().lower() for e in (row["events_mask"] or "").split(",")
            ]
            allowed_events = set()
            for m in mask_raw:
                if m == "pr":
                    allowed_events.add("pull_request")
                elif m == "issue":
                    allowed_events.add("issues")
                else:
                    allowed_events.add(m)

            if event in allowed_events:
                valid_integrations.append(row)

    if not valid_integrations:
        print("⚠️ Ignored: Signature mismatch or event not allowed")
        return JsonResponse({"status": "ignored"})

    print("✅ Signature verified")

    # -------------------------------
    # 8️⃣ Process & Store Event
    # -------------------------------
    for row in integrations:
        workspace_id = row["workspace_id"]
        _handle_github_event(
            workspace_id, repo_full_name, event, payload, delivery_id=delivery_id
        )

        print("✅ Event stored for workspace:", workspace_id)

    return JsonResponse({"status": "success"})


@csrf_exempt
@require_access_token
def notifications(request):
    user = getattr(request, "user_username", None)

    row = run_query(
        "SELECT email FROM users WHERE username=%s OR email=%s LIMIT 1",
        (user, user),
        fetchone=True,
    )
    user_email = row["email"] if row else user

    # ---------- GET ----------
    if request.method == "GET":
        only_unread = request.GET.get("unread") == "1"

        query = """
            SELECT
                id,
                type,
                JSON_UNQUOTE(JSON_EXTRACT(payload,'$.title')) AS title,
                JSON_UNQUOTE(JSON_EXTRACT(payload,'$.message')) AS message,
                is_read,
                created_at
            FROM notifications
            WHERE user_email = %s
        """
        params = [user_email]

        if only_unread:
            query += " AND is_read = 0"

        query += " ORDER BY created_at DESC"

        rows = run_query(query, tuple(params), fetchall=True)
        return JsonResponse({"status": "success", "data": rows})

    # ---------- POST ----------
    if request.method == "POST":
        data = get_request_data(request)

        if data.get("mark_all"):
            run_query(
                "DELETE FROM notifications WHERE user_email=%s",
                (user_email,),
            )
            return JsonResponse({"status": "success", "deleted": "all"})

        if data.get("id"):
            run_query(
                "UPDATE notifications SET is_read=1 WHERE id=%s AND user_email=%s",
                (data["id"], user_email),
            )
            return JsonResponse({"status": "success", "updated": data["id"]})

        return JsonResponse(
            {"status": "error", "message": "id or mark_all required"},
            status=400,
        )

    return JsonResponse(
        {"status": "error", "message": "Method not allowed"}, status=405
    )


@csrf_exempt
@require_access_token
def dm_send_message(request):
    user = getattr(request, "user_username", None)

    if request.method != "POST":
        return JsonResponse({"status": "error", "message": "POST required"}, status=405)

    data = get_request_data(request)
    ws_id = data.get("workspace_id")
    other_user_identifier = data.get("other_user")  # username or email
    body = (data.get("body") or "").strip()

    if not ws_id or not other_user_identifier or not body:
        return JsonResponse(
            {
                "status": "error",
                "message": "workspace_id, other_user and body are required",
            },
            status=400,
        )

    # Resolve current user & other_user to email
    sender_email = _resolve_to_email(user)
    recipient_email = _resolve_to_email(other_user_identifier)

    if not sender_email:
        return JsonResponse(
            {"status": "error", "message": "Could not resolve sender email"},
            status=400,
        )

    if not recipient_email:
        return JsonResponse(
            {"status": "error", "message": "Could not resolve other_user email"},
            status=400,
        )

    # Sender must be workspace member (Option B: no admin override)
    if not _is_workspace_member(sender_email, ws_id):
        return JsonResponse(
            {"status": "error", "message": "Forbidden (sender not in workspace)"},
            status=403,
        )

    # Other user must also be workspace member
    if not _is_workspace_member(recipient_email, ws_id):
        return JsonResponse(
            {"status": "error", "message": "Other user not in this workspace"},
            status=400,
        )

    run_query(
        """
        INSERT INTO dm_messages (workspace_id, sender_email, recipient_email, body)
        VALUES (%s, %s, %s, %s)
        """,
        (ws_id, sender_email, recipient_email, body),
    )
    dm_id = get_last_insert_id()

    # Optional notification
    try:
        title = "New direct message"
        msg = f'{sender_email} sent you a direct message: "{body[:150]}"'
        _insert_notification(
            user_email=recipient_email,
            workspace_id=ws_id,
            type_="dm_message",
            ref_id=dm_id,
            title=title,
            message=msg,
        )
    except Exception:
        logger.exception("[DM] Failed to insert notification")

    return JsonResponse({"status": "success", "dm_id": dm_id}, status=201)


@csrf_exempt
@require_access_token
def dm_list_messages(request):
    user = getattr(request, "user_username", None)

    if request.method != "POST":
        return JsonResponse({"status": "error", "message": "POST required"}, status=405)

    data = get_request_data(request)
    ws_id = data.get("workspace_id")
    other_user_identifier = data.get("other_user")

    if not ws_id or not other_user_identifier:
        return JsonResponse(
            {"status": "error", "message": "workspace_id and other_user are required"},
            status=400,
        )

    current_email = _resolve_to_email(user)
    other_email = _resolve_to_email(other_user_identifier)

    if not current_email or not other_email:
        return JsonResponse(
            {"status": "error", "message": "Could not resolve user emails"},
            status=400,
        )

    # Both must be workspace members
    if not _is_workspace_member(current_email, ws_id):
        return JsonResponse(
            {"status": "error", "message": "Forbidden (not workspace member)"},
            status=403,
        )

    if not _is_workspace_member(other_email, ws_id):
        return JsonResponse(
            {"status": "error", "message": "Other user not in this workspace"},
            status=400,
        )

    rows = run_query(
        """
        SELECT id, workspace_id, sender_email, recipient_email, body,
               is_edited, created_at, updated_at
        FROM dm_messages
        WHERE workspace_id = %s
          AND (
                (sender_email = %s AND recipient_email = %s)
             OR (sender_email = %s AND recipient_email = %s)
          )
        ORDER BY created_at ASC
        """,
        (ws_id, current_email, other_email, other_email, current_email),
        fetchall=True,
    )

    return JsonResponse({"status": "success", "data": rows})


@csrf_exempt
@require_access_token
def dm_edit_message(request):
    user = getattr(request, "user_username", None)

    if request.method != "POST":
        return JsonResponse({"status": "error", "message": "POST required"}, status=405)

    data = get_request_data(request)
    dm_id = data.get("id")
    new_body = (data.get("body") or "").strip()

    if not dm_id or not new_body:
        return JsonResponse(
            {"status": "error", "message": "id and body are required"},
            status=400,
        )

    # Resolve current user to email (username -> email if needed)
    current_email = _resolve_to_email(user)
    if not current_email:
        return JsonResponse(
            {"status": "error", "message": "Could not resolve current user email"},
            status=400,
        )

    # Load DM row
    row = run_query(
        """
        SELECT id, workspace_id, sender_email, recipient_email, body
        FROM dm_messages
        WHERE id = %s
        """,
        (dm_id,),
        fetchone=True,
    )

    if not row:
        return JsonResponse(
            {"status": "error", "message": "DM not found"},
            status=404,
        )

    if isinstance(row, dict):
        ws_id = row["workspace_id"]
        sender_email = row["sender_email"]
    else:
        # assuming: id, workspace_id, sender_email, recipient_email, body
        _, ws_id, sender_email, _, _ = row

    # Only the sender can edit (Option B – no admin override)
    if current_email != sender_email:
        return JsonResponse(
            {"status": "error", "message": "Forbidden (only sender can edit)"},
            status=403,
        )

    # Update body + mark edited
    run_query(
        """
        UPDATE dm_messages
        SET body = %s, is_edited = 1
        WHERE id = %s
        """,
        (new_body, dm_id),
    )

    return JsonResponse({"status": "success", "edited": True})


@csrf_exempt
@require_access_token
def dm_delete_message(request):
    user = getattr(request, "user_username", None)

    if request.method != "POST":
        return JsonResponse({"status": "error", "message": "POST required"}, status=405)

    data = get_request_data(request)
    dm_id = data.get("id")

    if not dm_id:
        return JsonResponse(
            {"status": "error", "message": "id required"},
            status=400,
        )

    # Resolve current user to email
    current_email = _resolve_to_email(user)
    if not current_email:
        return JsonResponse(
            {"status": "error", "message": "Could not resolve current user email"},
            status=400,
        )

    # Load DM row
    row = run_query(
        """
        SELECT id, workspace_id, sender_email, recipient_email, body
        FROM dm_messages
        WHERE id = %s
        """,
        (dm_id,),
        fetchone=True,
    )

    if not row:
        return JsonResponse(
            {"status": "error", "message": "DM not found"},
            status=404,
        )

    if isinstance(row, dict):
        ws_id = row["workspace_id"]
        sender_email = row["sender_email"]
    else:
        _, ws_id, sender_email, _, _ = row

    # Only sender can delete (Option B)
    if current_email != sender_email:
        return JsonResponse(
            {"status": "error", "message": "Forbidden (only sender can delete)"},
            status=403,
        )

    # Hard delete
    run_query("DELETE FROM dm_messages WHERE id = %s", (dm_id,))

    return JsonResponse({"status": "success", "deleted": True})


@csrf_exempt
@require_access_token
def project_story(request):
    if request.method != "POST":
        return JsonResponse(
            {"status": "error", "message": "POST required"},
            status=405,
        )

    data = get_request_data(request)
    workspace_id = data.get("workspace_id")

    if not workspace_id:
        return JsonResponse(
            {"status": "error", "message": "workspace_id is required"},
            status=400,
        )

    try:
        # -----------------------------
        # Time range (user controlled)
        # -----------------------------
        from_date = data.get("from_date")
        to_date = data.get("to_date")
        days = data.get("days")

        if from_date and to_date:
            start_dt = datetime.fromisoformat(from_date)
            end_dt = datetime.fromisoformat(to_date)
        else:
            try:
                days = int(days)
                if days <= 0 or days > 365:
                    raise ValueError
            except Exception:
                days = 60  # SAFE default for your old test data

            end_dt = datetime.utcnow()
            start_dt = end_dt - datetime.timedelta(days=days)

        # -----------------------------
        # GitHub pushes
        # -----------------------------
        github_pushes = run_query(
            """
            SELECT COUNT(*) AS c
            FROM activities
            WHERE workspace_id = %s
              AND type = 'github_push'
              AND created_at BETWEEN %s AND %s
            """,
            (workspace_id, start_dt, end_dt),
            fetchone=True,
        )["c"]

        # -----------------------------
        # Workspace updates
        # -----------------------------
        updates = run_query(
            """
            SELECT COUNT(*) AS c
            FROM activities
            WHERE workspace_id = %s
              AND type = 'workspace_update'
              AND created_at BETWEEN %s AND %s
            """,
            (workspace_id, start_dt, end_dt),
            fetchone=True,
        )["c"]

        # -----------------------------
        # Task activity (THIS IS THE FIX)
        # -----------------------------
        tasks = run_query(
            """
            SELECT
              COUNT(CASE WHEN type = 'task_created' THEN 1 END) AS created,
              COUNT(CASE WHEN type = 'task_updated' THEN 1 END) AS updated,
              COUNT(CASE WHEN type = 'task_deleted' THEN 1 END) AS deleted
            FROM activities
            WHERE workspace_id = %s
              AND type LIKE 'task_%%'
              AND created_at BETWEEN %s AND %s
            """,
            (workspace_id, start_dt, end_dt),
            fetchone=True,
        )

        # -----------------------------
        # Build summary
        # -----------------------------
        lines = []

        if github_pushes:
            lines.append(f"{github_pushes} code push(es) were made.")

        if updates:
            lines.append(f"{updates} project update(s) were shared.")

        if tasks["created"] or tasks["updated"] or tasks["deleted"]:
            lines.append(
                f"Tasks: {tasks['created']} created, "
                f"{tasks['updated']} updated, "
                f"{tasks['deleted']} deleted."
            )

        if not lines:
            lines.append("There was limited visible activity during this period.")

        return JsonResponse(
            {
                "status": "success",
                "workspace_id": workspace_id,
                "from": start_dt.isoformat(),
                "to": end_dt.isoformat(),
                "summary": " ".join(lines),
            }
        )

    except Exception as e:
        logger.exception(f"[Project Story] Error: {e}")
        return JsonResponse(
            {"status": "error", "message": "Failed to generate project story"},
            status=500,
        )


from django.http import JsonResponse
from django.views.decorators.http import require_GET
from django.views.decorators.csrf import csrf_exempt


@csrf_exempt
@require_access_token
def me_view(request):
    user_email = get_current_user(request)
    row = run_query(
        "SELECT email, username, full_name, is_admin, is_super_admin FROM users WHERE email=%s",
        (user_email,),
        fetchone=True,
    )
    if not row:
        return JsonResponse({"detail": "User not found"}, status=404)

    return JsonResponse(
        {
            "username": row["username"],
            "email": row["email"],
            "full_name": row["full_name"],
            "is_admin": bool(row["is_admin"]),
            "is_super_admin": bool(row["is_super_admin"]),
            "can_create_workspace": _can_create_workspace(user_email),
        },
        status=200,
    )


@csrf_exempt
@require_access_token
def super_admin_update_admin(request):
    actor = get_current_user(request)

    if not is_super_admin(actor):
        logger.warning(f"[SECURITY] Non-super-admin tried admin update: {actor}")
        return JsonResponse({"status": "error"}, status=403)

    data = get_request_data(request)
    target = data.get("email")
    is_admin_flag = data.get("is_admin")

    logger.info(f"[ADMIN] {actor} set admin={is_admin_flag} for {target}")

    run_query(
        "UPDATE users SET is_admin = %s WHERE email = %s",
        (1 if is_admin_flag else 0, target),
    )

    return JsonResponse({"status": "success"})


@csrf_exempt
@require_access_token
def my_workspaces(request):
    user = get_current_user(request)

    logger.info(f"[WORKSPACE] Fetch workspaces for {user}")

    rows = run_query(
        """
    SELECT
    w.id,
    w.name,
    w.description,
    m.role,
    COUNT(DISTINCT wm.user_email) AS member_count
    FROM workspaces w
    JOIN workspace_members m ON m.workspace_id = w.id
    LEFT JOIN workspace_members wm ON wm.workspace_id = w.id
    WHERE m.user_email = %s
    GROUP BY w.id, m.role
    ORDER BY w.created_at DESC
        """,
        (user,),
        fetchall=True,
    )

    return JsonResponse({"status": "success", "data": rows})


# admin stats


@csrf_exempt
@require_access_token
def admin_stats(request):
    actor = get_current_user(request)

    if not _is_admin(actor):
        return JsonResponse({"message": "Forbidden"}, status=403)

    users = run_query("SELECT COUNT(*) AS c FROM users", fetchone=True)["c"]

    active_users = run_query(
        """
        SELECT COUNT(*) AS c
        FROM presence
        WHERE status IN ('online', 'idle')
          AND last_seen >= DATE_SUB(NOW(), INTERVAL 15 MINUTE)
        """,
        fetchone=True,
    )["c"]

    admins = run_query(
        "SELECT COUNT(*) AS c FROM users WHERE is_admin = 1", fetchone=True
    )["c"]

    workspaces = run_query("SELECT COUNT(*) AS c FROM workspaces", fetchone=True)["c"]

    channels = run_query("SELECT COUNT(*) AS c FROM channels", fetchone=True)["c"]

    return JsonResponse(
        {
            "users": users,
            "active_users": active_users,
            "admins": admins,
            "workspaces": workspaces,
            "channels": channels,
        }
    )


@csrf_exempt
@require_access_token
def admin_workspace_overview(request, workspace_id):
    """
    Admin → workspace statistics + metadata
    """

    actor = get_current_user(request)

    # 🔐 Only admins allowed
    if not _is_admin(actor):
        return JsonResponse({"message": "Forbidden"}, status=403)

    # ===============================
    # Workspace info
    # ===============================
    ws = run_query(
        """
        SELECT id, name, description, created_by, created_at
        FROM workspaces
        WHERE id = %s
        """,
        (workspace_id,),
        fetchone=True,
    )

    if not ws:
        return JsonResponse({"message": "Workspace not found"}, status=404)

    # ===============================
    # Members count
    # ===============================
    members = run_query(
        """
        SELECT COUNT(*) AS c
        FROM workspace_members
        WHERE workspace_id = %s
        """,
        (workspace_id,),
        fetchone=True,
    )["c"]

    # ===============================
    # Leaders count
    # ===============================
    leaders = run_query(
        """
        SELECT COUNT(*) AS c
        FROM workspace_members
        WHERE workspace_id = %s AND role = 'leader'
        """,
        (workspace_id,),
        fetchone=True,
    )["c"]

    # ===============================
    # Owners count
    # ===============================
    owners = run_query(
        """
        SELECT COUNT(*) AS c
        FROM workspace_members
        WHERE workspace_id = %s AND role = 'owner'
        """,
        (workspace_id,),
        fetchone=True,
    )["c"]

    # ===============================
    # Channels count
    # ===============================
    channels = run_query(
        """
        SELECT COUNT(*) AS c
        FROM channels
        WHERE workspace_id = %s
        """,
        (workspace_id,),
        fetchone=True,
    )["c"]

    # ===============================
    # Response
    # ===============================
    return JsonResponse(
        {
            "status": "success",
            "data": {
                "workspace": ws,
                "stats": {
                    "members": members,
                    "leaders": leaders,
                    "owners": owners,
                    "channels": channels,
                },
            },
        }
    )


@csrf_exempt
@require_access_token
def admin_workspace_channels(request, workspace_id):
    actor = get_current_user(request)

    if not _is_admin(actor):
        return JsonResponse({"message": "Forbidden"}, status=403)

    rows = run_query(
        """
        SELECT
            c.id,
            c.name,
            COUNT(cm.user_email) AS member_count
        FROM channels c
        LEFT JOIN channel_members cm ON cm.channel_id = c.id
        WHERE c.workspace_id = %s
        GROUP BY c.id
        ORDER BY c.created_at ASC
        """,
        (workspace_id,),
        fetchall=True,
    )

    return JsonResponse(rows, safe=False)


@csrf_exempt
@require_access_token
def admin_user_workspaces(request, user_id):
    if not request.is_admin:
        return JsonResponse({"message": "Forbidden"}, status=403)

    # resolve email from id
    row = run_query(
        "SELECT email FROM users WHERE id=%s",
        (user_id,),
        fetchone=True,
    )

    if not row:
        return JsonResponse({"message": "User not found"}, status=404)

    email = row["email"]

    rows = run_query(
        """
        SELECT w.id, w.name, m.role
        FROM workspace_members m
        JOIN workspaces w ON w.id = m.workspace_id
        WHERE m.user_email = %s
        """,
        (email,),
        fetchall=True,
    )

    return JsonResponse(rows, safe=False)


@csrf_exempt
@require_access_token
def workspace_overview(request, workspace_id):
    user = get_current_user(request)

    if not can_manage_workspace(user, workspace_id):
        return JsonResponse({"message": "Forbidden"}, status=403)

    members = run_query(
        "SELECT COUNT(*) AS c FROM workspace_members WHERE workspace_id=%s",
        (workspace_id,),
        fetchone=True,
    )["c"]

    channels = run_query(
        "SELECT COUNT(*) AS c FROM channels WHERE workspace_id=%s",
        (workspace_id,),
        fetchone=True,
    )["c"]

    return JsonResponse(
        {
            "workspace_id": workspace_id,
            "members": members,
            "channels": channels,
        }
    )


@csrf_exempt
@require_access_token
def admin_list_users(request):
    actor = get_current_user(request)

    if not _is_admin(actor):
        return JsonResponse({"message": "Forbidden"}, status=403)

    rows = run_query(
        """
        SELECT
            id,
            email,
            full_name,
            is_admin,
            is_super_admin,
            created_at
        FROM users
        ORDER BY created_at DESC
        """,
        fetchall=True,
    )

    return JsonResponse({"status": "success", "data": rows})


@csrf_exempt
@require_access_token
def admin_set_user_role(request):
    actor = get_current_user(request)

    if not _is_admin(actor):
        return JsonResponse({"message": "Forbidden"}, status=403)

    data = get_request_data(request)
    email = data.get("email")
    is_admin = data.get("is_admin")

    if email is None or is_admin is None:
        return JsonResponse({"message": "email and is_admin required"}, status=400)

    run_query(
        "UPDATE users SET is_admin=%s WHERE email=%s",
        (1 if is_admin else 0, email),
    )

    return JsonResponse({"status": "success"})


@csrf_exempt
@require_access_token
def fetch_all_history_view(request):

    if request.method != "POST":
        return JsonResponse(
            {"status": "error", "message": "Method not allowed"},
            status=405,
        )

    data = get_request_data(request)

    ws_id = data.get("workspace_id")

    if not ws_id:
        return JsonResponse(
            {"status": "error", "message": "workspace_id required"},
            status=400,
        )

    actor = get_current_user(request)

    # 🔐 Reuse your existing permission logic
    if not can_manage_workspace(actor, ws_id):
        return JsonResponse({"status": "error"}, status=403)

    # 🔍 Get all connected repos for this workspace
    repos = run_query(
        """
        SELECT repo_full_name
        FROM github_repos
        WHERE workspace_id = %s
        AND is_active = 1
        """,
        (ws_id,),
        fetchall=True,
    )

    if not repos:
        return JsonResponse(
            {"status": "success", "message": "No connected repositories"}
        )

    # 🔄 Sync each repository
    for repo in repos:
        initial_repo_sync(repo["repo_full_name"], ws_id)

    return JsonResponse(
        {"status": "success", "message": "Repositories synced successfully"}
    )


@csrf_exempt
@require_access_token
def connect_repository(request):

    if request.method != "POST":
        return JsonResponse({"status": "error"}, status=405)

    data = get_request_data(request)

    ws_id = data.get("workspace_id")
    repo_full_name = data.get("repo_full_name")

    if not ws_id or not repo_full_name:
        return JsonResponse({"status": "error"}, status=400)

    actor = get_current_user(request)

    if not can_manage_workspace(actor, ws_id):
        return JsonResponse({"status": "error"}, status=403)

    # Save repo
    run_query(
        """
        INSERT INTO github_repos
        (workspace_id, repo_full_name, webhook_secret, is_active)
        VALUES (%s, %s, %s, 1)
        ON DUPLICATE KEY UPDATE webhook_secret=VALUES(webhook_secret), is_active=1
        """,
        (ws_id, repo_full_name, settings.GITHUB_WEBHOOK_SECRET),
    )

    # Initial Sync
    initial_repo_sync(repo_full_name, ws_id)

    return JsonResponse({"status": "success", "message": "Repository connected"})
