import logging
import jwt, uuid, datetime
import json
from datetime import datetime, timedelta, timezone
from django.conf import settings
from django.http import JsonResponse
from django.db import connection

logger = logging.getLogger("django")


# simple DB helper used by get_user_default_workspace
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


# ---------------------------------------------------------
# SAFE HELPERS — settings accessed inside functions only
# ---------------------------------------------------------
# ---------------------------------------------------------


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


# ---------------------------------------------------------
# OTP TOKEN
# ---------------------------------------------------------


def create_otp_token(username: str):
    payload = {
        "sub": username,
        "typ": "otp",
        "iat": int(_now_utc().timestamp()),
        "exp": int(_exp(get_otp_ttl()).timestamp()),
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm=get_jwt_alg())


# ---------------------------------------------------------
# ACCESS TOKEN
# ---------------------------------------------------------


def create_access_token(username):
    now = _now_utc()
    payload = {
        "sub": username,
        "typ": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + get_access_lifetime()).timestamp()),
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm=get_jwt_alg())


# ---------------------------------------------------------
# REFRESH TOKEN
# ---------------------------------------------------------


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


# ---------------------------------------------------------
# ID TOKEN
# ---------------------------------------------------------


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


# ---------------------------------------------------------
# DECODE TOKEN
# ---------------------------------------------------------


def decode_token(token, verify_exp=True):
    return jwt.decode(
        token,
        get_jwt_secret(),
        algorithms=[get_jwt_alg()],
        options={"verify_exp": verify_exp},
    )


# ---------------------------------------------------------
# REQUEST HELPERS
# ---------------------------------------------------------


def get_request_data(request):
    try:
        if not request.body:
            return {}
        return json.loads(request.body.decode("utf-8"))
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
    if not user_email or not workspace_id:
        return None

    row = run_query(
        """
        SELECT role
        FROM workspace_members
        WHERE user_email = %s AND workspace_id = %s
        """,
        (user_email, workspace_id),
        fetchone=True,
    )
    return row.get("role") if row else None


def _is_workspace_owner(user_email, workspace_id):
    return _get_workspace_role(user_email, workspace_id) == "owner"


def _can_create_workspace(user_email):
    """
    User can create workspace if:
    - is_admin = 1, OR
    - can_create_workspace = 1
    """
    if not user_email:
        return False

    row = run_query(
        "SELECT is_admin, can_create_workspace FROM users WHERE email = %s",
        (user_email,),
        fetchone=True,
    )
    if not row:
        return False

    return bool(row.get("is_admin") or row.get("can_create_workspace"))
