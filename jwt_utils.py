import logging
import jwt, uuid, datetime
import json
from datetime import datetime, timedelta, timezone
from django.conf import settings
from django.http import JsonResponse
from django.db import connection

import re
from django.conf import settings
from django.core.mail import send_mail
logger = logging.getLogger("django")


# -------------------------------------------------------------------------
# DB HELPER
# -------------------------------------------------------------------------
def run_query(sql, params=None, fetchone=False):
    """
    Execute a parameterized SQL query and return rows or a single row.
    - sql: SQL string with placeholders (%s)
    - params: tuple or list of parameters
    - fetchone: if True return a single row (or None)
    Returns: tuple(s) or None
    """
    params = params or ()
    with connection.cursor() as cursor:
        cursor.execute(sql, params)
        # If the statement didn't return rows
        if cursor.description is None:
            return None
        if fetchone:
            return cursor.fetchone()
        return cursor.fetchall()


# -------------------------------------------------------------------------
# SAFE HELPERS — settings accessed inside functions only
# -------------------------------------------------------------------------
def _now_utc():
    return datetime.now(timezone.utc)


def _exp(ttl):
    return _now_utc() + timedelta(seconds=ttl)


def get_jwt_secret():
    return getattr(settings, "JWT_SECRET", settings.SECRET_KEY)


def get_jwt_alg():
    return getattr(settings, "JWT_ALG", "HS256")


def get_otp_ttl():
    return getattr(settings, "JWT_OTP_TTL", 300)


def get_access_lifetime():
    return timedelta(minutes=10)


def get_refresh_lifetime():
    return timedelta(days=7)


def get_id_lifetime():
    return timedelta(minutes=10)


# -------------------------------------------------------------------------
# OTP TOKEN
# -------------------------------------------------------------------------
def create_otp_token(username: str):
    payload = {
        "sub": username,
        "typ": "otp",
        "iat": int(_now_utc().timestamp()),
        "exp": int(_exp(get_otp_ttl()).timestamp()),
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm=get_jwt_alg())


# -------------------------------------------------------------------------
# ACCESS TOKEN
# -------------------------------------------------------------------------
def create_access_token(username):
    now = _now_utc()
    payload = {
        "sub": username,
        "typ": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + get_access_lifetime()).timestamp()),
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm=get_jwt_alg())


# -------------------------------------------------------------------------
# REFRESH TOKEN
# -------------------------------------------------------------------------
def create_refresh_token(username):
    now = _now_utc()
    jti = uuid.uuid4().hex

    payload = {
        "sub": username,
        "typ": "refresh",
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int((now + get_refresh_lifetime()).timestamp()),
    }

    token = jwt.encode(payload, get_jwt_secret(), algorithm=get_jwt_alg())
    return token, jti, None  # compatibility


# -------------------------------------------------------------------------
# ID TOKEN
# -------------------------------------------------------------------------
def create_id_token(username, email=None, full_name=None):
    now = _now_utc()
    payload = {
        "sub": username,
        "typ": "id",
        "email": email,
        "name": full_name,
        "iat": int(now.timestamp()),
        "exp": int((now + get_id_lifetime()).timestamp()),
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm=get_jwt_alg())


# -------------------------------------------------------------------------
# DECODE TOKEN
# -------------------------------------------------------------------------
def decode_token(token, verify_exp=True):
    return jwt.decode(
        token,
        get_jwt_secret(),
        algorithms=[get_jwt_alg()],
        options={"verify_exp": verify_exp},
    )


# -------------------------------------------------------------------------
# REQUEST HELPERS
# -------------------------------------------------------------------------
def get_request_data(request):
    """Safely read JSON or form data."""
    try:
        if request.content_type and "application/json" in request.content_type:
            return json.loads(request.body.decode("utf-8"))
        return request.POST
    except Exception:
        return {}


def get_user_from_request(request):
    user = getattr(request, "user_username", None) or getattr(
        request, "user_email", None
    )
    if user:
        return user

    try:
        token = request.COOKIES.get("access_token")
        if token:
            payload = jwt.decode(token, get_jwt_secret(), algorithms=[get_jwt_alg()])
            return payload.get("sub") or payload.get("email")
    except jwt.ExpiredSignatureError:
        try:
            payload = jwt.decode(
                token,
                get_jwt_secret(),
                algorithms=[get_jwt_alg()],
                options={"verify_exp": False},
            )
            return payload.get("sub") or payload.get("email")
        except Exception:
            return None
    except Exception:
        return None

    return None


def get_user_default_workspace(user_email):
    """
    Returns the most recently created workspace where the user is a member.
    """
    row = run_query(
        """
        SELECT w.id, w.name
        FROM workspaces w
        JOIN workspace_members m ON m.workspace_id = w.id
        WHERE m.user_email=%s
        ORDER BY w.created_at DESC
        LIMIT 1
    """,
        (user_email,),
        fetchone=True,
    )
    return row


# -------------------------------------------------------------------------
# ROLE / PERMISSION HELPERS
# -------------------------------------------------------------------------
def _is_admin(user_identifier):
    """
    user_identifier is whatever require_access_token puts in request.user_username.
    It might be username or email, so we check both.
    Handles both tuple and dict rows from run_query.
    """
    logger.info(f"[_is_admin] Checking is_admin for identifier: {user_identifier}")
    if not user_identifier:
        return False

    row = run_query(
        """
        SELECT is_admin
        FROM users
        WHERE username = %s OR email = %s
        """,
        (user_identifier, user_identifier),
        fetchone=True,
    )
    logger.info(f"[_is_admin] DB row: {row}")

    if not row:
        return False

    # row can be a tuple like (1,) or a dict like {"is_admin": 1}
    if isinstance(row, dict):
        value = row.get("is_admin")
    else:
        # assume tuple / list, first column is is_admin
        value = row[0]

    return bool(value)

def _get_workspace_role(user_email, workspace_id):
    """
    Return the role ('owner', 'member', etc.) of this user in this workspace.
    Works whether run_query returns a dict or a tuple.
    """
    if not user_email or not workspace_id:
        return None

    logger.info(f"[_get_workspace_role] user_email={user_email}, workspace_id={workspace_id}")

    row = run_query(
        """
        SELECT role
        FROM workspace_members
        WHERE workspace_id = %s AND user_email = %s
        """,
        (workspace_id, user_email),
        fetchone=True,
    )
    logger.info(f"[_get_workspace_role] DB row: {row}")

    if not row:
        return None

    # row can be dict or tuple
    if isinstance(row, dict):
        return row.get("role")
    else:
        # assume single-column tuple like ('owner',)
        return row[0]


def _is_workspace_owner(user_email, workspace_id):
    return _get_workspace_role(user_email, workspace_id) == "owner"


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


# -------------------------------------------------------------------------
# OTHER HELPERS
# -------------------------------------------------------------------------
def _handle_github_event(ws_id, repo_full_name, event, events_mask, payload):
    raise NotImplementedError


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


def _insert_notification(user_email, workspace_id, type_, ref_id, title, message):
    try:
        run_query(
            """
            INSERT INTO notifications (user_email, workspace_id, type, ref_id, title, message)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (user_email, workspace_id, type_, ref_id, title, message),
        )
    except Exception as e:
        logger.exception(f"[Notification] Failed to insert: {e}")


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
            or row.get("is_revoked") is True
        )
    except Exception:
        logger.exception(f"[is_refresh_revoked] Error checking jti={jti}")
        # Fail closed: consider token revoked on error
        return True




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


def _insert_notification(user_email, workspace_id, type_, ref_id, title, message):
    try:
        run_query(
            """
            INSERT INTO notifications (user_email, workspace_id, type, ref_id, title, message)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (user_email, workspace_id, type_, ref_id, title, message),
        )
    except Exception as e:
        logger.exception(f"[Notification] Failed to insert: {e}")


def _send_notification_email(to_email, subject, body):
    """
    Optional email notification. Fails silently if email not configured.
    """
    try:
        from_email = getattr(settings, "EMAIL_HOST_USER", None) or "no-reply@example.com"
        send_mail(subject, body, from_email, [to_email], fail_silently=True)
    except Exception as e:
        logger.exception(f"[Email] Failed to send notification email: {e}")



def _get_workspace_for_channel(channel_id):
    row = run_query(
        "SELECT workspace_id, name FROM channels WHERE id = %s",
        (channel_id,),
        fetchone=True,
    )
    if not row:
        return None, None

    if isinstance(row, dict):
        return row["workspace_id"], row.get("name")
    else:
        # assuming columns: workspace_id, name
        return row[0], row[1] if len(row) > 1 else None


def _username_to_email(username):
    """
    Map @username to user's email via users table.
    """
    row = run_query(
        "SELECT email FROM users WHERE username = %s",
        (username,),
        fetchone=True,
    )
    if not row:
        return None
    if isinstance(row, dict):
        return row.get("email")
    return row[0]





def _process_message_mentions(channel_id, message_id, body, sender_email):
    """
    - Detect @username and notify that user
    - Detect #task123 and notify task assignee/creator
    """
    ws_id, channel_name = _get_workspace_for_channel(channel_id)
    if not ws_id:
        return

    # ----- 1) @username mentions -----
    # Pattern: @username  (letters, numbers, underscore, dot, dash)
    mentioned_usernames = set(re.findall(r"@([A-Za-z0-9_.-]+)", body or ""))

    for uname in mentioned_usernames:
        target_email = _username_to_email(uname)
        if not target_email:
            continue

        # Insert notification
        title = f"You were mentioned in #{channel_name or 'channel'}"
        message = f"{sender_email} mentioned you in a message: \"{body[:150]}\""

        _insert_notification(
            user_email=target_email,
            workspace_id=ws_id,
            type_="mention_message",
            ref_id=message_id,
            title=title,
            message=message,
        )

        # Optional email
        _send_notification_email(
            to_email=target_email,
            subject=title,
            body=message,
        )

    # ----- 2) #task123 mentions -----
    # Pattern: #task123  (case insensitive, #TASK123 also ok)
    task_matches = set(re.findall(r"#task(\d+)", body or "", flags=re.IGNORECASE))

    for task_id_str in task_matches:
        try:
            task_id = int(task_id_str)
        except ValueError:
            continue

        task_row = run_query(
            """
            SELECT id, workspace_id, title, assignee_email, created_by
            FROM tasks
            WHERE id = %s
            """,
            (task_id,),
            fetchone=True,
        )
        if not task_row:
            continue

        # handle tuple vs dict
        if isinstance(task_row, dict):
            task_ws_id = task_row["workspace_id"]
            task_title = task_row["title"]
            assignee_email = task_row.get("assignee_email")
            created_by = task_row["created_by"]
        else:
            # assuming order: id, workspace_id, title, assignee_email, created_by
            _, task_ws_id, task_title, assignee_email, created_by = task_row

        # Only notify if the task belongs to the same workspace
        if task_ws_id != ws_id:
            continue

        title = f"Task mentioned: {task_title}"
        msg = f"{sender_email} mentioned task #{task_id} in #{channel_name or 'channel'}: \"{body[:150]}\""

        recipients = set(filter(None, [assignee_email, created_by]))

        for target in recipients:
            _insert_notification(
                user_email=target,
                workspace_id=ws_id,
                type_="task_mentioned",
                ref_id=task_id,
                title=title,
                message=msg,
            )
            _send_notification_email(
                to_email=target,
                subject=title,
                body=msg,
            )
