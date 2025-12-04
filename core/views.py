# core/views.py
import json
import hashlib
import logging
import datetime
import secrets
from django.conf import settings
from django.utils import timezone
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from httpcore import request
import hmac
import hashlib
from django.views.decorators.http import require_POST


def _handle_github_event(ws_id, repo_full_name, event, events_mask, payload):
    raise NotImplementedError


# DB helpers
from db import run_query, save_refresh_token, revoke_refresh_token, get_last_insert_id

# JWT helpers
from jwt_utils import (
    _get_workspace_role,
    _is_admin,
    _is_workspace_owner,
    decode_token,
    create_access_token,
    create_refresh_token,
    create_id_token,
)

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from db import run_query
from core.decorators import require_access_token
from jwt_utils import get_request_data


def _insert_activity(workspace_id, actor_email, type_, ref_id, summary):
    try:
        run_query(
            """
            INSERT INTO activities (workspace_id, actor_email, type, ref_id, summary)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (workspace_id, actor_email, type_, ref_id, summary),
        )
    except Exception as e:
        logger.exception(f"[Activity] Failed to insert: {e}")


def _get_current_user_email(request):
    return getattr(request, "user_username", None)


def _get_default_workspace_id(user_email):
    row = run_query(
        """
        SELECT w.id
        FROM workspaces w
        JOIN workspace_members m ON m.workspace_id = w.id
        WHERE m.user_email = %s
        ORDER BY w.created_at DESC
        LIMIT 1
        """,
        (user_email,),
        fetchone=True,
    )
    return row["id"] if row else None


# Decorators
from core.decorators import require_access_token

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
# HELPERS
# -----------------------------------------------------------------------------


def get_request_data(request):
    """Safely read JSON or form data."""
    try:
        if request.content_type and "application/json" in request.content_type:
            return json.loads(request.body.decode("utf-8"))
        return request.POST
    except Exception:
        return {}


def is_refresh_revoked(jti):
    """Check DB to see if a refresh token jti has been revoked."""
    try:
        row = run_query(
            "SELECT is_revoked FROM refresh_tokens WHERE jti=%s",
            (jti,),
            fetchone=True,
        )
        # If no record found, treat as revoked for safety
        if not row:
            return True
        return bool(
            row.get("is_revoked")
            or row.get("is_revoked") == 1
            or row.get("is_revoked") == True
        )
    except Exception:
        logger.exception(f"[is_refresh_revoked] Error checking jti={jti}")
        # Fail closed: consider token revoked on error
        return True


def _can_create_workspace(user_identifier):
    """
    User can create workspace if:
    - is_admin = 1, OR
    - can_create_workspace = 1

    We match by username OR email.
    Handles both tuple and dict rows from run_query.
    """
    logger.info(f"[_can_create_workspace] Checking for: {user_identifier}")
    if not user_identifier:
        return False

    row = run_query(
        """
        SELECT is_admin, can_create_workspace
        FROM users
        WHERE username = %s OR email = %s
        """,
        (user_identifier, user_identifier),
        fetchone=True,
    )
    logger.info(f"[_can_create_workspace] DB row: {row}")

    if not row:
        return False

    if isinstance(row, dict):
        is_admin = row.get("is_admin")
        can_create = row.get("can_create_workspace")
    else:
        # assume tuple-like: (is_admin, can_create_workspace)
        is_admin = row[0]
        can_create = row[1] if len(row) > 1 else 0

    return bool(is_admin or can_create)


def _is_global_leader(user_email):
    row = run_query(
        "SELECT can_create_workspace FROM users WHERE email = %s",
        (user_email,),
        fetchone=True,
    )
    return bool(row and row.get("can_create_workspace"))


def _user_is_member_of_workspace(user_email, workspace_id):
    """
    Return True if this user is a member of the workspace (any role).
    Works with both tuple and dict rows.
    """
    row = run_query(
        """
        SELECT 1
        FROM workspace_members
        WHERE user_email = %s AND workspace_id = %s
        LIMIT 1
        """,
        (user_email, workspace_id),
        fetchone=True,
    )
    return bool(row)


def _user_is_owner_of_workspace(user_email, workspace_id):
    """
    Return True if this user is an owner for this workspace.
    """
    row = run_query(
        """
        SELECT 1
        FROM workspace_members
        WHERE user_email = %s AND workspace_id = %s AND role = 'owner'
        LIMIT 1
        """,
        (user_email, workspace_id),
        fetchone=True,
    )
    return bool(row)
def _user_is_member_of_workspace(user_email, workspace_id):
    """
    Return True if this user is a member of the workspace (any role).
    Works with both tuple and dict rows.
    """
    row = run_query(
        """
        SELECT 1
        FROM workspace_members
        WHERE user_email = %s AND workspace_id = %s
        LIMIT 1
        """,
        (user_email, workspace_id),
        fetchone=True,
    )
    return bool(row)


def _user_is_owner_of_workspace(user_email, workspace_id):
    """
    Return True if this user is an owner for this workspace.
    """
    row = run_query(
        """
        SELECT 1
        FROM workspace_members
        WHERE user_email = %s AND workspace_id = %s AND role = 'owner'
        LIMIT 1
        """,
        (user_email, workspace_id),
        fetchone=True,
    )
    return bool(row)


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

    # Generate a simple 6-digit OTP
    otp_code = str(datetime.datetime.now().microsecond % 1000000).zfill(6)

    run_query(
        "INSERT INTO otp_codes (username, otp_code) VALUES (%s, %s)",
        (user["username"], otp_code),
    )

    logger.info(f"[OTP] OTP generated for {user['username']}")

    # Send email
    try:
        from django.core.mail import send_mail

        send_mail(
            "Your OTP Code",
            f"Your OTP: {otp_code}",
            settings.EMAIL_HOST_USER,
            [email],
        )
    except Exception as e:
        logger.exception(f"[OTP EMAIL] {e}")
        return JsonResponse({"status": "error", "message": "Email failed"}, status=500)

    return JsonResponse({"status": "success", "message": f"OTP sent to {email}"})


# -----------------------------------------------------------------------------
# VERIFY OTP → LOGIN
# -----------------------------------------------------------------------------
@csrf_exempt
def verify_otp(request):
    if request.method != "POST":
        return JsonResponse({"status": "error", "message": "POST required"}, status=405)

    data = get_request_data(request)
    email = data.get("email")
    otp = data.get("otp")

    if not email or not otp:
        return JsonResponse(
            {"status": "error", "message": "Email and OTP required"}, status=400
        )

    try:
        user = run_query(
            "SELECT username, email, full_name FROM users WHERE email=%s",
            (email,),
            fetchone=True,
        )
        if not user:
            return JsonResponse(
                {"status": "error", "message": "User not found"}, status=404
            )

        otp_record = run_query(
            "SELECT otp_code, created_at FROM otp_codes WHERE username=%s ORDER BY created_at DESC LIMIT 1",
            (user["username"],),
            fetchone=True,
        )
        if not otp_record:
            return JsonResponse(
                {"status": "error", "message": "OTP not found"}, status=404
            )

        if otp_record["otp_code"] != otp:
            return JsonResponse(
                {"status": "error", "message": "Invalid OTP"}, status=401
            )

        otp_time = otp_record["created_at"].replace(tzinfo=None)
        now = timezone.now().replace(tzinfo=None)
        if now - otp_time > datetime.timedelta(minutes=5):
            return JsonResponse(
                {"status": "error", "message": "OTP expired"}, status=401
            )

        # OTP valid → generate tokens
        username = user["username"]

        access_token = create_access_token(username)
        refresh_token, jti, _ = create_refresh_token(username)
        id_token = create_id_token(username, user["email"], user.get("full_name"))

        r_payload = decode_token(refresh_token)
        save_refresh_token(jti, username, r_payload["exp"])

        run_query("DELETE FROM otp_codes WHERE username=%s", (username,))

        response = JsonResponse({"status": "success", "message": "Login successful!"})
        response.set_cookie("access_token", access_token, max_age=600, **COOKIE_KWARGS)
        response.set_cookie(
            "refresh_token", refresh_token, max_age=7 * 86400, **COOKIE_KWARGS
        )
        response.set_cookie("id_token", id_token, max_age=600, **COOKIE_KWARGS)
        return response

    except Exception as e:
        logger.exception(e)
        return JsonResponse({"status": "error", "message": str(e)}, status=500)


# -----------------------------------------------------------------------------
# LOGOUT
# -----------------------------------------------------------------------------


@csrf_exempt
def logout(request):
    if request.method != "POST":
        return JsonResponse({"status": "error", "message": "POST required"}, status=405)

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
        return JsonResponse({"status": "error", "message": str(e)}, status=500)


# -----------------------------------------------------------------------------
# PROTECTED: WORKSPACES
# -----------------------------------------------------------------------------


@csrf_exempt
@require_access_token
def workspaces(request):
    user = getattr(request, "user_username", None)

    # GET list – unchanged (only my workspaces)
    if request.method == "GET":
        rows = run_query(
            """
            SELECT DISTINCT w.*
            FROM workspaces w
            JOIN workspace_members m ON m.workspace_id = w.id
            WHERE m.user_email = %s
            ORDER BY w.created_at DESC
            """,
            (user,),
            fetchall=True,
        )
        return JsonResponse({"status": "success", "data": rows})

    # POST create – now only admin or project leader can create
    if request.method == "POST":
        if not _can_create_workspace(user):
            return JsonResponse(
                {"status": "error", "message": "Not allowed to create workspace"},
                status=403,
            )

        data = get_request_data(request)
        name = data.get("name")
        desc = data.get("description", "")

        if not name:
            return JsonResponse(
                {"status": "error", "message": "Name required"}, status=400
            )

        run_query(
            "INSERT INTO workspaces (name, description, created_by) VALUES (%s,%s,%s)",
            (name, desc, user),
        )
        ws_id = get_last_insert_id()

        run_query(
            "INSERT INTO workspace_members (workspace_id, user_email, role) VALUES (%s,%s,'owner')",
            (ws_id, user),
        )

        return JsonResponse({"status": "success", "workspace_id": ws_id}, status=201)

    return JsonResponse(
        {"status": "error", "message": "Method not allowed"}, status=405
    )


@csrf_exempt
@require_access_token
def workspace_updates_view(request):
    """
    GET    /api/workspace-updates/?workspace_id=1
    POST   /api/workspace-updates/          (create new update)
    PATCH  /api/workspace-updates/          (edit existing)
    DELETE /api/workspace-updates/          (delete existing)

    Permissions:
    - List: any member of workspace (or admin)
    - Create: any member (or you can restrict to owner/leader later)
    - Edit/Delete: author OR workspace owner OR admin
    """
    user_email = getattr(request, "user_username", None)

    # Helper: find user's latest workspace (same idea as channels view)
    def _get_default_workspace_id():
        row = run_query(
            """
            SELECT w.id
            FROM workspaces w
            JOIN workspace_members m ON m.workspace_id = w.id
            WHERE m.user_email = %s
            ORDER BY w.created_at DESC
            LIMIT 1
            """,
            (user_email,),
            fetchone=True,
        )
        return row["id"] if row else None

    # Helper: find user's latest workspace (same idea as channels view)
    def _get_default_workspace_id():
        row = run_query(
            """
            SELECT w.id
            FROM workspaces w
            JOIN workspace_members m ON m.workspace_id = w.id
            WHERE m.user_email = %s
            ORDER BY w.created_at DESC
            LIMIT 1
            """,
            (user_email,),
            fetchone=True,
        )
        return row["id"] if row else None

    # --------------------- GET: list updates ---------------------
    if request.method == "GET":
        ws_id = request.GET.get("workspace_id")

        # if not given, pick latest workspace where user is a member
        if not ws_id:
            ws_id = _get_default_workspace_id()

        if not ws_id:
            return JsonResponse(
                {"status": "error", "message": "No workspace found"},
                status=404,
            )

        # permission: admin or member
        if not _is_admin(user_email):
            role = _get_workspace_role(user_email, ws_id)
            if not role:
                return JsonResponse(
                    {"status": "error", "message": "Forbidden"},
                    status=403,
                )

        rows = run_query(
            """
            SELECT
                id,
                workspace_id,
                channel_id,
                title,
                body,
                status,
                update_type,
                created_by,
                created_at,
                updated_at
            FROM workspace_updates
            WHERE workspace_id = %s
            ORDER BY created_at DESC
            """,
            (ws_id,),
            fetchall=True,
        )

        return JsonResponse(
            {
                "status": "success",
                "workspace_id": ws_id,
                "data": rows,
            }
        )
    # For write ops we’ll parse body once
    data = get_request_data(request)


@csrf_exempt
@require_access_token
def workspace_updates_view(request):
    user_email = getattr(request, "user_username", None)

    # --------------------- GET: list updates ---------------------
    if request.method == "GET":
        ws_id = request.GET.get("workspace_id")

        # if not passed, use latest workspace where user is member
        if not ws_id:
            ws_id = _get_default_workspace_id(user_email)

        if not ws_id:
            return JsonResponse(
                {"status": "error", "message": "No workspace found"},
                status=404,
            )

        # permission: admin or member of that workspace
        if not _is_admin(user_email):
            role = _get_workspace_role(user_email, ws_id)
            if not role:
                return JsonResponse(
                    {"status": "error", "message": "Forbidden"},
                    status=403,
                )

        rows = run_query(
            """
            SELECT
                id,
                workspace_id,
                channel_id,
                title,
                body,
                status,
                update_type,
                created_by,
                created_at,
                updated_at
            FROM workspace_updates
            WHERE workspace_id = %s
            ORDER BY created_at DESC
            """,
            (ws_id,),
            fetchall=True,
        )

        return JsonResponse({"status": "success", "data": rows})

    # --------------------- POST / PATCH / DELETE ---------------------
    # (these parts can stay exactly as I gave before)
    data = get_request_data(request)

    # ... POST / PATCH / DELETE logic unchanged ...

    # --------------------- POST: create update ---------------------
    if request.method == "POST":
        ws_id = data.get("workspace_id")
        title = (data.get("title") or "").strip()
        body = (data.get("body") or "").strip()
        status_val = (data.get("status") or "info").strip()
        update_type = (data.get("update_type") or "general").strip()
        channel_id = data.get("channel_id")  # optional

        if not ws_id or not title or not body:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "workspace_id, title and body are required",
                },
                status=400,
            )

        # permission: admin or member
        if not _is_admin(user_email):
            role = _get_workspace_role(user_email, ws_id)
            if not role:
                return JsonResponse(
                    {"status": "error", "message": "Forbidden"},
                    status=403,
                )

        run_query(
            """
            INSERT INTO workspace_updates (
                workspace_id, channel_id, title, body, status, update_type, created_by
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (ws_id, channel_id, title, body, status_val, update_type, user_email),
        )
        update_id = get_last_insert_id()

        # also push into activities feed
        summary = f"{user_email} posted an update: {title}"
        _insert_activity(
            workspace_id=ws_id,
            actor_email=user_email,
            type_="workspace_update",
            ref_id=update_id,
            summary=summary,
        )

        return JsonResponse(
            {"status": "success", "update_id": update_id},
            status=201,
        )

    # --------------------- PATCH: edit update ---------------------
    if request.method == "PATCH":
        update_id = data.get("id")
        if not update_id:
            return JsonResponse(
                {"status": "error", "message": "id required"},
                status=400,
            )

        # load existing row
        row = run_query(
            """
            SELECT
                id, workspace_id, created_by, title, body, status, update_type
            FROM workspace_updates
            WHERE id = %s
            """,
            (update_id,),
            fetchone=True,
        )

        if not row:
            return JsonResponse(
                {"status": "error", "message": "Update not found"},
                status=404,
            )

        ws_id = row["workspace_id"]
        created_by = row["created_by"]

        # permission: author OR workspace owner OR admin
        if not _is_admin(user_email):
            role = _get_workspace_role(user_email, ws_id)
            is_owner = role == "owner"
            if user_email != created_by and not is_owner:
                return JsonResponse(
                    {"status": "error", "message": "Forbidden"},
                    status=403,
                )

        # Prepare fields to update (partial update)
        new_title = (data.get("title") or row["title"]).strip()
        new_body = (data.get("body") or row["body"]).strip()
        new_status = (data.get("status") or row["status"]).strip()
        new_type = (data.get("update_type") or row["update_type"]).strip()

        run_query(
            """
            UPDATE workspace_updates
            SET title = %s,
                body = %s,
                status = %s,
                update_type = %s
            WHERE id = %s
            """,
            (new_title, new_body, new_status, new_type, update_id),
        )

        return JsonResponse({"status": "success", "message": "Update edited"})

    # --------------------- DELETE: remove update ---------------------
    if request.method == "DELETE":
        update_id = data.get("id")
        if not update_id:
            return JsonResponse(
                {"status": "error", "message": "id required"},
                status=400,
            )

        # load existing row
        row = run_query(
            """
            SELECT id, workspace_id, created_by
            FROM workspace_updates
            WHERE id = %s
            """,
            (update_id,),
            fetchone=True,
        )

        if not row:
            return JsonResponse(
                {"status": "error", "message": "Update not found"},
                status=404,
            )

        ws_id = row["workspace_id"]
        created_by = row["created_by"]

        # permission: author OR workspace owner OR admin
        if not _is_admin(user_email):
            role = _get_workspace_role(user_email, ws_id)
            is_owner = role == "owner"
            if user_email != created_by and not is_owner:
                return JsonResponse(
                    {"status": "error", "message": "Forbidden"},
                    status=403,
                )

        run_query(
            "DELETE FROM workspace_updates WHERE id = %s",
            (update_id,),
        )

        return JsonResponse({"status": "success", "message": "Update deleted"})

    return JsonResponse(
        {"status": "error", "message": "Method not allowed"}, status=405
    )


# -----------------------------------------------------------------------------
# PROTECTED: CHANNELS
@csrf_exempt
@require_access_token
def channels(request):
    user = getattr(request, "user_username", None)

    # Helper: find default workspace for this user
    def get_default_workspace_id():
        # If admin: pick the most recently created workspace globally
        if _is_admin(user):
            row = run_query(
                """
                SELECT id
                FROM workspaces
                ORDER BY created_at DESC
                LIMIT 1
                """,
                fetchone=True,
            )
            return row["id"] if row else None

        # Non-admin: pick latest workspace where user is a member
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
        return row["id"] if row else None

    # Small helper: check if user can access given workspace
    def _user_can_access_workspace(ws_id: int) -> bool:
        if not ws_id:
            return False
        # Admin can always access
        if _is_admin(user):
            return True
        # Otherwise, must be a member of this workspace
        role = _get_workspace_role(user, ws_id)
        return role is not None

    # ---------------------------------------------------
    # CREATE CHANNEL
    # ---------------------------------------------------
    if request.method == "POST":
        data = get_request_data(request)
        ws_id = data.get("workspace_id") or get_default_workspace_id()
        name = (data.get("name") or "").strip()
        is_private = 1 if data.get("is_private") else 0

        if not ws_id:
            return JsonResponse(
                {"status": "error", "message": "No workspace found"},
                status=404,
            )

        # ✅ PERMISSION CHECK: must be admin or member of this workspace
        if not _user_can_access_workspace(ws_id):
            return JsonResponse(
                {"status": "error", "message": "Forbidden"},
                status=403,
            )

        if not name:
            return JsonResponse(
                {"status": "error", "message": "Name required"},
                status=400,
            )

        run_query(
            "INSERT INTO channels (workspace_id, name, is_private) VALUES (%s,%s,%s)",
            (ws_id, name, is_private),
        )
        ch_id = get_last_insert_id()

        return JsonResponse(
            {
                "status": "success",
                "workspace_id": ws_id,
                "channel_id": ch_id,
            },
            status=201,
        )

    # ---------------------------------------------------
    # LIST CHANNELS FOR WORKSPACE
    # ---------------------------------------------------
    if request.method == "GET":
        ws_id = request.GET.get("workspace_id")
        if not ws_id:
            ws_id = get_default_workspace_id()

        if not ws_id:
            return JsonResponse(
                {"status": "error", "message": "No workspace found"},
                status=404,
            )

        # ✅ PERMISSION CHECK: must be admin or member of this workspace
        if not _user_can_access_workspace(ws_id):
            return JsonResponse(
                {"status": "error", "message": "Forbidden"},
                status=403,
            )

        rows = run_query(
            """
            SELECT id, name, is_private
            FROM channels
            WHERE workspace_id = %s
            ORDER BY id DESC
            """,
            (ws_id,),
            fetchall=True,
        )

        return JsonResponse(
            {
                "status": "success",
                "workspace_id": ws_id,
                "data": rows,
            }
        )

    return JsonResponse(
        {"status": "error", "message": "Method not allowed"},
        status=405,
    )


# @csrf_exempt
# @require_access_token
# def channels(request):
#     user = getattr(request, "user_username", None)

#     # Helper: find default workspace for this user
#     def get_default_workspace_id():
#         # If admin: pick the most recently created workspace globally
#         if _is_admin(user):
#             row = run_query(
#                 """
#                 SELECT id
#                 FROM workspaces
#                 ORDER BY created_at DESC
#                 LIMIT 1
#                 """,
#                 fetchone=True,
#             )
#             return row["id"] if row else None

#         # Non-admin: pick latest workspace where user is a member
#         row = run_query(
#             """
#             SELECT w.id
#             FROM workspaces w
#             JOIN workspace_members m ON m.workspace_id = w.id
#             WHERE m.user_email = %s
#             ORDER BY w.created_at DESC
#             LIMIT 1
#             """,
#             (user,),
#             fetchone=True,
#         )
#         return row["id"] if row else None

#     # Small helper: check if user can access given workspace
#     def _user_can_access_workspace(ws_id: int) -> bool:
#         if not ws_id:
#             return False
#         # Admin can always access
#         if _is_admin(user):
#             return True
#         # Otherwise, must be a member of this workspace
#         role = _get_workspace_role(user, ws_id)
#         return role is not None

#     # ---------------------------------------------------
#     # CREATE CHANNEL
#     # ---------------------------------------------------
#     if request.method == "POST":
#         data = get_request_data(request)
#         ws_id = data.get("workspace_id") or get_default_workspace_id()
#         name = (data.get("name") or "").strip()
#         is_private = 1 if data.get("is_private") else 0

#         if not ws_id:
#             return JsonResponse(
#                 {"status": "error", "message": "No workspace found"},
#                 status=404,
#             )

#         # ✅ PERMISSION CHECK: must be admin or member of this workspace
#         if not _user_can_access_workspace(ws_id):
#             return JsonResponse(
#                 {"status": "error", "message": "Forbidden"},
#                 status=403,
#             )

#         if not name:
#             return JsonResponse(
#                 {"status": "error", "message": "Name required"},
#                 status=400,
#             )

#         run_query(
#             "INSERT INTO channels (workspace_id, name, is_private) VALUES (%s,%s,%s)",
#             (ws_id, name, is_private),
#         )
#         ch_id = get_last_insert_id()

#         return JsonResponse(
#             {
#                 "status": "success",
#                 "workspace_id": ws_id,
#                 "channel_id": ch_id,
#             },
#             status=201,
#         )

#     # ---------------------------------------------------
#     # LIST CHANNELS FOR WORKSPACE
#     # ---------------------------------------------------
#     if request.method == "GET":
#         ws_id = request.GET.get("workspace_id")
#         if not ws_id:
#             ws_id = get_default_workspace_id()

#         if not ws_id:
#             return JsonResponse(
#                 {"status": "error", "message": "No workspace found"},
#                 status=404,
#             )

#         # ✅ PERMISSION CHECK: must be admin or member of this workspace
#         if not _user_can_access_workspace(ws_id):
#             return JsonResponse(
#                 {"status": "error", "message": "Forbidden"},
#                 status=403,
#             )

#         rows = run_query(
#             """
#             SELECT id, name, is_private
#             FROM channels
#             WHERE workspace_id = %s
#             ORDER BY id DESC
#             """,
#             (ws_id,),
#             fetchall=True,
#         )

#         return JsonResponse(
#             {
#                 "status": "success",
#                 "workspace_id": ws_id,
#                 "data": rows,
#             }
#         )

#     return JsonResponse(
#         {"status": "error", "message": "Method not allowed"},
#         status=405,
#     )

# -----------------------------------------------------------------------------
# PROTECTED: MESSAGES
# -----------------------------------------------------------------------------


@csrf_exempt
@require_access_token
def messages(request):
    user = getattr(request, "user_username", None)

    if request.method == "GET":
        channel_id = request.GET.get("channel_id")
        if not channel_id:
            return JsonResponse(
                {"status": "error", "message": "channel_id required"}, status=400
            )

        rows = run_query(
            """
            SELECT id, sender_email, body, created_at
            FROM messages
            WHERE channel_id=%s
            ORDER BY created_at ASC
            """,
            (channel_id,),
            fetchall=True,
        )

        return JsonResponse({"status": "success", "data": rows})

    elif request.method == "POST":
        data = get_request_data(request)
        channel_id = data.get("channel_id")
        body = (data.get("body") or "").strip()

        if not channel_id or not body:
            return JsonResponse(
                {"status": "error", "message": "Missing fields"}, status=400
            )

        run_query(
            """
            INSERT INTO messages (channel_id, sender_email, body)
            VALUES (%s, %s, %s)
            """,
            (channel_id, user, body),
        )

        msg_id = get_last_insert_id()
        return JsonResponse({"status": "success", "message_id": msg_id}, status=201)

    else:
        return JsonResponse(
            {"status": "error", "message": "Method not allowed"}, status=405
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
    user = getattr(request, "user_username", None)

    if request.method != "POST":
        return JsonResponse({"status": "error", "message": "POST required"}, status=405)

    data = get_request_data(request)

    ws_id = data.get("workspace_id")
    title = data.get("title")
    description = data.get("description", "")
    priority = data.get("priority", "normal")
    assignee = data.get("assignee_email")

    if not ws_id or not title:
        return JsonResponse(
            {"status": "error", "message": "workspace_id and title are required"},
            status=400,
        )

    # ✅ Permission: admin OR workspace member
    if not _is_admin(user) and not _user_is_member_of_workspace(user, ws_id):
        return JsonResponse(
            {"status": "error", "message": "Forbidden"},
            status=403,
        )

    run_query(
        """
        INSERT INTO tasks (workspace_id, created_by, title, description, priority, assignee_email)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (ws_id, user, title, description, priority, assignee),
    )

    task_id = get_last_insert_id()

    # 🔁 Log into activities
    summary = f"{user} created task: {title}"
    _insert_activity(
        workspace_id=ws_id,
        actor_email=user,
        type_="task_created",
        ref_id=task_id,
        summary=summary,
    )

    return JsonResponse({"status": "success", "task_id": task_id}, status=201)

@csrf_exempt
@require_access_token
def task_update(request):
    user = getattr(request, "user_username", None)

    if request.method != "POST":
        return JsonResponse({"status": "error", "message": "POST required"}, status=405)

    data = get_request_data(request)
    task_id = data.get("task_id")

    if not task_id:
        return JsonResponse(
            {"status": "error", "message": "task_id required"}, status=400
        )

    # Load existing task to check permissions
    task_row = run_query(
        """
        SELECT id, workspace_id, created_by, assignee_email, title
        FROM tasks
        WHERE id = %s
        """,
        (task_id,),
        fetchone=True,
    )

    if not task_row:
        return JsonResponse(
            {"status": "error", "message": "Task not found"},
            status=404,
        )

    # handle tuple vs dict
    if isinstance(task_row, dict):
        ws_id = task_row["workspace_id"]
        created_by = task_row["created_by"]
        assignee_email = task_row.get("assignee_email")
        title = task_row["title"]
    else:
        # assuming columns order: id, workspace_id, created_by, assignee_email, title
        _, ws_id, created_by, assignee_email, title = task_row

    # ✅ Permission:
    #   - Admin OR
    #   - Workspace owner OR
    #   - Task creator OR
    #   - Task assignee
    if not _is_admin(user):
        is_owner = _user_is_owner_of_workspace(user, ws_id)
        is_creator = (created_by == user)
        is_assignee = (assignee_email == user)

        if not (is_owner or is_creator or is_assignee):
            return JsonResponse(
                {"status": "error", "message": "Forbidden"},
                status=403,
            )

    fields = []
    params = []

    for field in ["title", "description", "status", "priority", "assignee_email"]:
        if field in data:
            fields.append(f"{field}=%s")
            params.append(data[field])

    if not fields:
        return JsonResponse(
            {"status": "error", "message": "Nothing to update"}, status=400
        )

    params.append(task_id)

    run_query(f"UPDATE tasks SET {', '.join(fields)} WHERE id=%s", params)

    # 🔁 Log into activities
    summary = f"{user} updated task: {title} (#{task_id})"
    _insert_activity(
        workspace_id=ws_id,
        actor_email=user,
        type_="task_updated",
        ref_id=task_id,
        summary=summary,
    )

    return JsonResponse({"status": "success", "updated": True})


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
    if not _is_admin(user) and not _user_is_member_of_workspace(user, ws_id):
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
def task_delete(request):
    user = getattr(request, "user_username", None)

    if request.method != "POST":
        return JsonResponse({"status": "error", "message": "POST required"}, status=405)

    task_id = get_request_data(request).get("task_id")
    if not task_id:
        return JsonResponse(
            {"status": "error", "message": "task_id required"}, status=400
        )

    # Load existing task to check permissions and get workspace + title
    task_row = run_query(
        """
        SELECT id, workspace_id, created_by, assignee_email, title
        FROM tasks
        WHERE id = %s
        """,
        (task_id,),
        fetchone=True,
    )

    if not task_row:
        return JsonResponse(
            {"status": "error", "message": "Task not found"},
            status=404,
        )

    if isinstance(task_row, dict):
        ws_id = task_row["workspace_id"]
        created_by = task_row["created_by"]
        assignee_email = task_row.get("assignee_email")
        title = task_row["title"]
    else:
        _, ws_id, created_by, assignee_email, title = task_row

    # ✅ Permission:
    #   - Admin OR
    #   - Workspace owner OR
    #   - Task creator OR
    #   - Task assignee
    if not _is_admin(user):
        is_owner = _user_is_owner_of_workspace(user, ws_id)
        is_creator = (created_by == user)
        is_assignee = (assignee_email == user)

        if not (is_owner or is_creator or is_assignee):
            return JsonResponse(
                {"status": "error", "message": "Forbidden"},
                status=403,
            )

    run_query("DELETE FROM tasks WHERE id=%s", (task_id,))

    # 🔁 Log into activities
    summary = f"{user} deleted task: {title} (#{task_id})"
    _insert_activity(
        workspace_id=ws_id,
        actor_email=user,
        type_="task_deleted",
        ref_id=task_id,
        summary=summary,
    )

    return JsonResponse({"status": "success", "deleted": True})


@csrf_exempt
@require_access_token
def admin_users(request):
    """
    GET /api/admin/users/

    Returns all users with key flags useful for admin panel.
    """
    current_user = _get_current_user_email(request)

    if not _is_admin(current_user):
        return JsonResponse({"status": "error", "message": "Forbidden"}, status=403)

    if request.method != "GET":
        return JsonResponse(
            {"status": "error", "message": "Method not allowed"}, status=405
        )

    rows = run_query(
        """
        SELECT
            id,
            username,
            email,
            full_name,
            phone_number,
            COALESCE(is_admin, 0) AS is_admin,
            COALESCE(can_create_workspace, 0) AS can_create_workspace,
            COALESCE(is_active, 1) AS is_active,
            created_at,
            last_login
        FROM users
        ORDER BY created_at DESC
        """,
        fetchall=True,
    )

    return JsonResponse({"status": "success", "data": rows})


@csrf_exempt
@require_access_token
def admin_update_user_roles(request):
    """
    POST /api/admin/users/update-role/

    Body JSON:
    {
      "email": "user@example.com",
      "is_admin": true/false,               (optional)
      "can_create_workspace": true/false    (optional)
    }
    """
    current_user = _get_current_user_email(request)

    if not _is_admin(current_user):
        return JsonResponse({"status": "error", "message": "Forbidden"}, status=403)

    if request.method != "POST":
        return JsonResponse(
            {"status": "error", "message": "Method not allowed"}, status=405
        )

    data = get_request_data(request)
    target_email = (data.get("email") or "").strip().lower()
    is_admin = data.get("is_admin")
    can_create = data.get("can_create_workspace")

    if not target_email:
        return JsonResponse(
            {"status": "error", "message": "email required"}, status=400
        )

    fields = []
    params = []

    if is_admin is not None:
        fields.append("is_admin = %s")
        params.append(1 if bool(is_admin) else 0)

    if can_create is not None:
        fields.append("can_create_workspace = %s")
        params.append(1 if bool(can_create) else 0)

    if not fields:
        return JsonResponse(
            {"status": "error", "message": "Nothing to update"},
            status=400,
        )

    params.append(target_email)

    run_query(
        f"UPDATE users SET {', '.join(fields)} WHERE email = %s",
        tuple(params),
    )

    return JsonResponse({"status": "success", "message": "User updated"})


@csrf_exempt
@require_access_token
def admin_workspaces(request):
    """
    GET /api/admin/workspaces/

    Returns all workspaces with member_count and creator info.
    """
    current_user = _get_current_user_email(request)

    if not _is_admin(current_user):
        return JsonResponse({"status": "error", "message": "Forbidden"}, status=403)

    if request.method != "GET":
        return JsonResponse(
            {"status": "error", "message": "Method not allowed"}, status=405
        )

    rows = run_query(
        """
        SELECT
            w.id,
            w.name,
            w.description,
            w.created_by,
            w.created_at,
            COUNT(m.user_email) AS member_count
        FROM workspaces w
        LEFT JOIN workspace_members m ON m.workspace_id = w.id
        GROUP BY w.id
        ORDER BY w.created_at DESC
        """,
        fetchall=True,
    )

    return JsonResponse({"status": "success", "data": rows})


@csrf_exempt
@require_access_token
def account(request):
    user_email = getattr(request, "user_username", None)
    if not user_email:
        return JsonResponse(
            {"status": "error", "message": "Unauthenticated"}, status=401
        )

    row = run_query(
        """
        SELECT
            id,
            username,
            email,
            full_name,
            phone_number,
            COALESCE(is_admin, 0) AS is_admin,
            COALESCE(can_create_workspace, 0) AS can_create_workspace,
            COALESCE(is_active, 1) AS is_active,
            created_at,
            last_login
        FROM users
        WHERE email = %s
        """,
        (user_email,),
        fetchone=True,
    )

    if not row:
        return JsonResponse(
            {"status": "error", "message": "User not found"}, status=404
        )

    return JsonResponse({"status": "success", "data": row})


@csrf_exempt
@require_access_token
def github_integrations(request):
    user = getattr(request, "user_username", None)

    # ------------------ LIST ------------------
    if request.method == "GET":
        ws_id = request.GET.get("workspace_id")
        if not ws_id:
            return JsonResponse(
                {"status": "error", "message": "workspace_id required"},
                status=400,
            )

        # permission: admin or member of workspace
        if not _is_admin(user):
            role = _get_workspace_role(user, ws_id)
            if not role:
                return JsonResponse(
                    {"status": "error", "message": "Forbidden"},
                    status=403,
                )

        rows = run_query(
            """
            SELECT
                id,
                workspace_id,
                repo_full_name,
                events_mask,
                is_active,
                created_at
            FROM github_repos
            WHERE workspace_id = %s
            ORDER BY created_at DESC
            """,
            (ws_id,),
            fetchall=True,
        )

        return JsonResponse({"status": "success", "data": rows})
    # ------------------ CREATE ------------------
    if request.method == "POST":
        data = get_request_data(request)
        ws_id = data.get("workspace_id")
        repo_full_name = (data.get("repo_full_name") or "").strip()
        events_mask = (data.get("events_mask") or "push,pr,issues").strip()

        if not ws_id or not repo_full_name:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "workspace_id and repo_full_name required",
                },
                status=400,
            )

        # permission: admin or owner of workspace
        if not _is_admin(user):
            role = _get_workspace_role(user, ws_id)
            if role != "owner":
                return JsonResponse(
                    {
                        "status": "error",
                        "message": "Only owner or admin can configure GitHub",
                    },
                    status=403,
                )

        # generate a new webhook secret
        webhook_secret = secrets.token_hex(32)

        try:
            run_query(
                """
                INSERT INTO github_repos (
                    workspace_id,
                    repo_full_name,
                    events_mask,
                    webhook_secret,
                    is_active
                ) VALUES (%s, %s, %s, %s, 1)
                """,
                (ws_id, repo_full_name, events_mask, webhook_secret),
            )
        except Exception as e:
            logger.exception(f"[GitHub Integration] Insert error: {e}")
            return JsonResponse(
                {"status": "error", "message": "Failed to create integration"},
                status=500,
            )

        # return info but do NOT expose secret in normal responses
        return JsonResponse(
            {
                "status": "success",
                "message": "GitHub integration created",
                "data": {
                    "workspace_id": ws_id,
                    "repo_full_name": repo_full_name,
                    "events_mask": events_mask,
                },
            },
            status=201,
        )
    # ------------------ DELETE / DISABLE ------------------
    if request.method == "DELETE":
        data = get_request_data(request)
        integ_id = data.get("id")
        ws_id = data.get("workspace_id")

        if not integ_id or not ws_id:
            return JsonResponse(
                {"status": "error", "message": "id and workspace_id required"},
                status=400,
            )

        # permission: admin or owner
        if not _is_admin(user):
            role = _get_workspace_role(user, ws_id)
            if role != "owner":
                return JsonResponse(
                    {
                        "status": "error",
                        "message": "Only owner or admin can modify GitHub integrations",
                    },
                    status=403,
                )

        run_query(
            "DELETE FROM github_repos WHERE id = %s AND workspace_id = %s",
            (integ_id, ws_id),
        )

        return JsonResponse({"status": "success", "message": "Integration removed"})

    return JsonResponse(
        {"status": "error", "message": "Method not allowed"},
        status=405,
    )


@csrf_exempt
def github_webhook(request):
    """
    POST /api/github/webhook/

    Validate GitHub webhook and insert rows into `activities`.
    Uses github_repos.webhook_secret for HMAC.
    """
    if request.method != "POST":
        return JsonResponse(
            {"status": "error", "message": "Method not allowed"}, status=405
        )

    body = request.body

    # --- parse JSON ---
    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception:
        logger.exception("[GH] Invalid JSON payload")
        return JsonResponse({"status": "error", "message": "Invalid JSON"}, status=400)

    repo_full_name = (payload.get("repository") or {}).get("full_name")
    if not repo_full_name:
        logger.warning("[GH] Missing repository.full_name in payload")
        return JsonResponse({"status": "success"}, status=200)  # ignore

    # --- lookup integration row ---
    row = run_query(
        """
        SELECT workspace_id, webhook_secret, events_mask
        FROM github_repos
        WHERE repo_full_name = %s
          AND is_active = 1
        LIMIT 1
        """,
        (repo_full_name,),
        fetchone=True,
    )

    if not row:
        logger.warning("[GH] No active github_repos row for %s", repo_full_name)
        return JsonResponse({"status": "success"}, status=200)

    workspace_id = row["workspace_id"]
    secret = row["webhook_secret"] or ""
    events_mask = row["events_mask"] or ""
    mask = [m.strip() for m in events_mask.lower().split(",") if m.strip()]

    # --- verify signature ---
    sig_header = request.META.get("HTTP_X_HUB_SIGNATURE_256", "")
    if not sig_header.startswith("sha256="):
        logger.warning("[GH] Missing/invalid X-Hub-Signature-256")
        return JsonResponse({"status": "error", "message": "Bad signature"}, status=403)

    sent_sig = sig_header.split("=", 1)[1]
    mac = hmac.new(secret.encode("utf-8"), msg=body, digestmod=hashlib.sha256)
    expected_sig = mac.hexdigest()

    if not hmac.compare_digest(sent_sig, expected_sig):
        logger.warning("[GH] Signature mismatch for repo %s", repo_full_name)
        return JsonResponse(
            {"status": "error", "message": "Invalid signature"}, status=403
        )

    # --- event type ---
    event = request.META.get("HTTP_X_GITHUB_EVENT", "")
    if event == "ping":
        logger.info("[GH] Ping for %s", repo_full_name)
        return JsonResponse({"status": "success", "message": "pong"})

    logger.info("[GH] Event=%s repo=%s", event, repo_full_name)

    actor = None
    ref_id = None  # we'll normalize later
    activity_type = None
    summary = None

    # ================== PUSH ==================
    if event == "push" and "push" in mask:
        pusher = (payload.get("pusher") or {}).get("name") or "GitHub"
        ref = payload.get("ref", "")  # e.g. refs/heads/main
        branch = ref.split("/")[-1] if ref else ""
        commits = payload.get("commits") or []
        commit_count = len(commits)

        actor = pusher
        # IMPORTANT: commit SHA is a long string; your ref_id column is numeric.
        # Keep ref_id NULL for push so DB never complains.
        ref_id = None
        activity_type = "github_push"
        summary = (
            f"{pusher} pushed {commit_count} commit(s) to {branch} in {repo_full_name}"
        )

    # ================== PULL REQUEST ==================
    elif event == "pull_request" and "pr" in mask:
        action = payload.get("action")
        pr = payload.get("pull_request") or {}
        title = pr.get("title")
        number = pr.get("number")  # small integer
        user = (pr.get("user") or {}).get("login") or "GitHub"
        merged = pr.get("merged", False)

        actor = user
        ref_id = number

        if action == "opened":
            activity_type = "github_pr_opened"
            summary = f"{user} opened PR #{number}: {title}"
        elif action == "closed" and merged:
            activity_type = "github_pr_merged"
            summary = f"{user} merged PR #{number}: {title}"
        elif action == "closed":
            activity_type = "github_pr_closed"
            summary = f"{user} closed PR #{number}: {title}"
        else:
            logger.info("[GH] PR action %s ignored", action)

    # ================== ISSUES ==================
    elif event == "issues" and "issues" in mask:
        action = payload.get("action")
        issue = payload.get("issue") or {}
        title = issue.get("title")
        number = issue.get("number")  # small integer
        user = (issue.get("user") or {}).get("login") or "GitHub"

        actor = user
        ref_id = number

        if action == "opened":
            activity_type = "github_issue_opened"
            summary = f"{user} opened issue #{number}: {title}"
        elif action == "closed":
            activity_type = "github_issue_closed"
            summary = f"{user} closed issue #{number}: {title}"
        else:
            logger.info("[GH] Issue action %s ignored", action)

    # If we didn't map anything, just acknowledge
    if not activity_type:
        logger.info("[GH] Event %s ignored for repo %s", event, repo_full_name)
        return JsonResponse({"status": "success", "message": "ignored"})

    # --- normalize ref_id for DB (numeric or NULL) ---
    ref_id_db = None
    if ref_id is not None:
        try:
            ref_id_db = int(ref_id)
        except (TypeError, ValueError):
            # If it's not an int (e.g. commit SHA), keep NULL
            ref_id_db = None

    # --- insert into activities ---
    try:
        run_query(
            """
            INSERT INTO activities (workspace_id, actor_email, type, ref_id, summary)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (workspace_id, actor, activity_type, ref_id_db, summary),
        )
        logger.info(
            "[GH] Activity row created: ws=%s type=%s", workspace_id, activity_type
        )
    except Exception as e:
        logger.exception("[GH] Failed to insert activity: %s", e)
        return JsonResponse({"status": "error", "message": "DB error"}, status=500)

    return JsonResponse({"status": "success"})
