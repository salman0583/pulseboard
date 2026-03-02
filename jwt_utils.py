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
import requests
logger = logging.getLogger("django")

from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
# core/realtime.py
import re

def safe_group_name(value: str) -> str:
    """
    Convert any string (email, username, etc.)
    into a Channels-safe group name.
    """
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", value)

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
def create_access_token(username, jti=None):
    """
    Create an access token.
    If jti is provided, it ties this access token to the same session as the refresh token.
    """
    now = _now_utc()
    payload = {
        "sub": username,
        "typ": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + get_access_lifetime()).timestamp()),
    }

    if jti is not None:
        payload["jti"] = jti

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
# REFRESH TOKEN PERSISTENCE / REVOCATION
# -------------------------------------------------------------------------
def save_refresh_token(jti, username, exp_timestamp):
    """
    Store refresh token session in DB.
    exp_timestamp is the JWT 'exp' (UNIX seconds).
    """
    expires_at = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)

    run_query(
        """
        INSERT INTO refresh_tokens (jti, username, expires_at, is_revoked, created_at)
        VALUES (%s, %s, %s, 0, SYSTIMESTAMP)
        """,
        (jti, username, expires_at),
    )


def revoke_refresh_token(jti):
    """
    Mark a refresh token / session as revoked.
    """
    run_query(
        "UPDATE refresh_tokens SET is_revoked = 1 WHERE jti = %s",
        (jti,),
    )


def is_refresh_token_revoked(jti) -> bool:
    """
    Return True if the session is revoked or not found.
    """
    row = run_query(
        "SELECT is_revoked FROM refresh_tokens WHERE jti = %s",
        (jti,),
        fetchone=True,
    )
    if row is None:
        # Unknown session -> treat as invalid
        return True
    return bool(row[0])


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
    # """
    # user_identifier is whatever require_access_token puts in request.user_username.
    # It might be username or email, so we check both.
    # Handles both tuple and dict rows from run_query.
    # """
    # logger.info(f"[_is_admin] Checking is_admin for identifier: {user_identifier}")
    # if not user_identifier:
    #     return False

    # row = run_query(
    #     """
    #     SELECT is_admin
    #     FROM users
    #     WHERE username = %s OR email = %s
    #     """,
    #     (user_identifier, user_identifier),
    #     fetchone=True,
    # )
    # logger.info(f"[_is_admin] DB row: {row}")

    # if not row:
    #     return False

    # # row can be a tuple like (1,) or a dict like {"is_admin": 1}
    # if isinstance(row, dict):
    #     value = row.get("is_admin")
    # else:
    #     # assume tuple / list, first column is is_admin
    #     value = row[0]

    return bool(value)
def _is_admin(user_email):
    row = run_query(
        """
        SELECT is_admin
        FROM users
        WHERE email = %s AND is_active = 1
        """,
        (user_email,),
        fetchone=True,
    )

    if not row:
        return False

    # handle both dict and tuple
    if isinstance(row, dict):
        return bool(row.get("is_admin"))

    # tuple case: SELECT is_admin → first column
    return bool(row and row[0])


def _get_workspace_role(user_email, ws_id):
    row = run_query(
        "SELECT role FROM workspace_members WHERE user_email=%s AND workspace_id=%s",
        (user_email, ws_id),
        fetchone=True,
    )

    if not row:
        return None

    if isinstance(row, dict):
        return row.get("role")

    return row[0]


def _is_workspace_leader(user_email, workspace_id):
    return _get_workspace_role(user_email, workspace_id) == "leader"


def _is_workspace_member(user_email, workspace_id):
    return _get_workspace_role(user_email, workspace_id) in ("leader", "member")

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



def _user_is_owner_of_workspace(user_email, workspace_id):
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


def _resolve_to_email(identifier):
    """
    Takes either a username or an email and returns a canonical email string.

    - If it already looks like an email (contains '@'), return as-is.
    - Else, treat it as username and look up the email in users table.
    """
    if not identifier:
        return None

    identifier = str(identifier).strip()

    # If it already looks like an email, just return it
    if "@" in identifier:
        return identifier

    # Otherwise, treat as username -> find email
    row = run_query(
        "SELECT email FROM users WHERE username = %s",
        (identifier,),
        fetchone=True,
    )

    if not row:
        return None

    if isinstance(row, dict):
        return row.get("email")
    else:
        # single-column tuple
        return row[0]


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



def _user_is_owner_of_workspace(user_email, workspace_id):
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





from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer



def _broadcast_activity(workspace_id, activity_data):
    """
    Send activity to WebSocket listeners of this workspace.
    """
    try:
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            f"activity_{workspace_id}",
            {
                "type": "activity.message",
                "data": activity_data,
            },
        )
        logger.info("[ACTIVITY][WS] broadcasted ws=%s", workspace_id)
    except Exception:
        logger.exception("[ACTIVITY][WS] broadcast failed ws=%s", workspace_id)
        
        

def broadcast_notification(user_email: str, data: dict):
    """
    Send notification ONLY to a single user.
    """
    try:
        channel_layer = get_channel_layer()

        group_name = f"notifications_{safe_group_name(user_email)}"

        async_to_sync(channel_layer.group_send)(
            group_name,
            {
                "type": "notification_message",
                "data": data,
            },
        )

        logger.info(
            "[NOTIFICATION][WS_SENT] to=%s group=%s",
            user_email,
            group_name,
        )

    except Exception:
        logger.exception(
            "[NOTIFICATION][WS_FAILED] to=%s",
            user_email,
        )
    channel_layer = get_channel_layer()
    group = f"notifications_{safe_group_name(user_email)}"

    try:
        async_to_sync(channel_layer.group_send)(
            group,
            {
                "type": "notification_message",
                "data": data,
            },
        )
        logger.info("[NOTIFICATION][WS_SENT] to=%s", user_email)

    except Exception:
        logger.exception("[NOTIFICATION][WS_FAILED] to=%s", user_email)
        
def get_current_user(request):
    return getattr(request, "user_username", None)
       
       
def is_super_admin(email):
    row = run_query(
        "SELECT is_super_admin FROM users WHERE email = %s AND is_active = 1",
        (email,),
        fetchone=True,
    )

    # row is a tuple like (1,) or (0,)
    return bool(row and row[0])

            
def can_manage_workspace(user_email, workspace_id):
    role = _get_workspace_role(user_email, workspace_id)
    return (
        _is_admin(user_email) or
        role in ("owner", "leader")
    )

def can_assign_leader(user_email, workspace_id):
    role = _get_workspace_role(user_email, workspace_id)
    return (
        _is_admin(user_email) or
        role == "owner"
    )
 
 
 
def can_access_channel(user_email, channel_id):
    channel = run_query(
        "SELECT is_private, workspace_id FROM channels WHERE id = %s",
        (channel_id,),
        fetchone=True,
    )

    if not channel:
        return False

    if not channel["is_private"]:
        return True

    row = run_query(
        """
        SELECT 1 FROM channel_members
        WHERE channel_id = %s AND user_email = %s
        """,
        (channel_id, user_email),
        fetchone=True,
    )
    return bool(row)
       
        
        
def _handle_github_event(ws_id, repo_full_name, event, payload, delivery_id=None):
    """
    Process a GitHub event (from webhook or sync), store it, and broadcast.
    """
    actor = None
    action = None
    entity_type = None
    entity_id = None
    branch = None
    title = None
    message = None
    commit_count = None
    html_url = None
    github_created_at = None

    # -------- PUSH / COMMITS --------
    if event == "push":
        # Webhook payload vs REST API payload differ slightly
        if "pusher" in payload:
            actor = payload.get("pusher", {}).get("name")
            branch = payload.get("ref", "").replace("refs/heads/", "")
            commit_count = len(payload.get("commits", []))
            entity_type = "commit"
            message = payload.get("head_commit", {}).get("message")
            html_url = payload.get("compare")
            github_created_at = payload.get("head_commit", {}).get("timestamp")
        else:
            # REST API (commit object)
            actor = payload.get("commit", {}).get("author", {}).get("name")
            entity_type = "commit"
            entity_id = payload.get("sha")
            message = payload.get("commit", {}).get("message")
            html_url = payload.get("html_url")
            github_created_at = payload.get("commit", {}).get("author", {}).get("date")

    # -------- PULL REQUEST --------
    elif event == "pull_request":
        pr = payload.get("pull_request", {})
        actor = pr.get("user", {}).get("login")
        action = payload.get("action")
        entity_type = "pull_request"
        entity_id = pr.get("id")
        title = pr.get("title")
        message = pr.get("body")
        html_url = pr.get("html_url")
        branch = pr.get("head", {}).get("ref")
        github_created_at = pr.get("created_at")

    # -------- ISSUE --------
    elif event == "issues":
        issue = payload.get("issue", {})
        actor = issue.get("user", {}).get("login")
        action = payload.get("action")
        entity_type = "issue"
        entity_id = issue.get("id")
        title = issue.get("title")
        message = issue.get("body")
        html_url = issue.get("html_url")
        github_created_at = issue.get("created_at")

    else:
        logger.warning(f"[GITHUB Webhook] Unsupported event: {event}")
        return False

    try:
        run_query(
            """
            INSERT IGNORE INTO github_activity_events (
                workspace_id, repo_full_name, delivery_id, event_type, action,
                actor, entity_type, entity_id, branch, title, message,
                commit_count, html_url, github_created_at, payload
            )
            VALUES (%s,%s,%s,%s,%s, %s,%s,%s,%s,%s, %s,%s,%s,%s,%s)
            """,
            (
                ws_id, repo_full_name, delivery_id, event, action,
                actor, entity_type, entity_id, branch, title, message,
                commit_count, html_url, github_created_at, json.dumps(payload)
            ),
        )

        # 📣 Broadcast update
        _broadcast_activity(ws_id, {
            "type": "github_event",
            "event": event,
            "repo": repo_full_name,
            "actor": actor,
            "action": action,
            "title": title or message[:100] if message else "GitHub Update",
            "url": html_url,
            "timestamp": github_created_at or datetime.now().isoformat()
        })
        return True
    except Exception as e:
        logger.exception(f"[GITHUB] Error saving/broadcasting event: {e}")
        return False


def initial_repo_sync(repo_full_name, workspace_id):
    """
    Fetch history for a repository and store it.
    """
    headers = {
        "Authorization": f"Bearer {settings.GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json"
    }
    base_url = f"https://api.github.com/repos/{repo_full_name}"

    # 1. Commits
    resp = requests.get(f"{base_url}/commits?per_page=30", headers=headers)
    if resp.status_code == 200:
        for commit in resp.json():
            _handle_github_event(workspace_id, repo_full_name, "push", commit)

    # 2. PRs
    resp = requests.get(f"{base_url}/pulls?state=all&per_page=15", headers=headers)
    if resp.status_code == 200:
        for pr in resp.json():
            # Mocking payload for PR
            _handle_github_event(workspace_id, repo_full_name, "pull_request", {"pull_request": pr, "action": "synced"})

    # 3. Issues
    resp = requests.get(f"{base_url}/issues?state=all&per_page=15", headers=headers)
    if resp.status_code == 200:
        for issue in resp.json():
            if "pull_request" in issue: continue
            _handle_github_event(workspace_id, repo_full_name, "issues", {"issue": issue, "action": "synced"})

    logger.info(f"✅ Initial sync complete for {repo_full_name}")
