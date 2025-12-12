import logging
import MySQLdb
import configparser
import os
from pathlib import Path
from contextlib import closing
from datetime import datetime, timezone
logger = logging.getLogger("django")

# ===========================
# Load config.ini
# ===========================
BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = os.path.join(BASE_DIR, "config.ini")

if not os.path.exists(CONFIG_FILE):
    raise FileNotFoundError(f"config.ini not found at: {CONFIG_FILE}")

config = configparser.ConfigParser()
config.read(CONFIG_FILE)

if "mysql" not in config:
    raise KeyError("Missing [mysql] section in config.ini")

db_cfg = config["mysql"]


# ===========================
# Create MySQL connection
# ===========================
def get_connection():
    return MySQLdb.connect(
        host=db_cfg.get("HOST"),
        user=db_cfg.get("USER"),
        passwd=db_cfg.get("PASSWORD"),
        db=db_cfg.get("NAME"),
        port=db_cfg.getint("PORT"),
        charset="utf8mb4",
    )


# ===========================
# Generic SQL query runner
# ===========================
def run_query(query, params=None, fetchone=False, fetchall=False):
    conn = get_connection()
    try:
        with closing(conn.cursor(MySQLdb.cursors.DictCursor)) as cursor:
            cursor.execute(query, params or ())
            if fetchone:
                return cursor.fetchone()
            if fetchall:
                return cursor.fetchall()
            conn.commit()
    except Exception as e:
        conn.rollback()
        print("❌ DB Error:", e)
        raise
    finally:
        conn.close()


# ===========================
# REFRESH TOKEN HELPERS
# Production-Ready
# ===========================

def save_refresh_token(jti, username, exp_ts):
    """
    Save a new refresh token.
    exp_ts is UNIX timestamp from JWT payload["exp"].
    """
    expires_at = datetime.fromtimestamp(exp_ts, tz=timezone.utc).replace(tzinfo=None)

    run_query(
        """
        INSERT INTO refresh_tokens (jti, username, is_revoked, issued_at, expires_at)
        VALUES (%s, %s, 0, NOW(), %s)
        """,
        (jti, username, expires_at),
    )


def revoke_refresh_token(jti):
    """Mark a refresh token as revoked."""
    run_query(
        "UPDATE refresh_tokens SET is_revoked = 1 WHERE jti = %s",
        (jti,),
    )


def is_refresh_revoked(jti):
    """
    Return True if token is revoked OR not found.
    Missing token = unsafe = treat as revoked.
    """
    row = run_query(
        "SELECT is_revoked FROM refresh_tokens WHERE jti=%s",
        (jti,),
        fetchone=True,
    )
    if not row:
        return True
    return bool(row["is_revoked"])


def get_refresh_row(jti):
    """Optional helper to inspect token."""
    return run_query(
        "SELECT * FROM refresh_tokens WHERE jti = %s",
        (jti,),
        fetchone=True,
    )


# ===========================
# OPTIONAL: fetch last auto id
# ===========================
def get_last_insert_id():
    row = run_query(
        "SELECT LAST_INSERT_ID() AS id",
        fetchone=True,
    )
    return row["id"] if row and "id" in row else None


from contextlib import closing
import MySQLdb

# ... your existing get_connection, run_query, etc ...

from contextlib import closing
import MySQLdb

# ... your existing get_connection and run_query ...

def insert_and_get_id(query, params=None):
    """
    Execute an INSERT and return the auto-increment id
    using cursor.lastrowid on the SAME connection.
    """
    conn = get_connection()
    try:
        with closing(conn.cursor(MySQLdb.cursors.DictCursor)) as cursor:
            cursor.execute(query, params or ())
            last_id = cursor.lastrowid
            print("🔎 insert_and_get_id: lastrowid =", last_id)
            conn.commit()
            return last_id
    except Exception as e:
        conn.rollback()
        print("❌ DB Error (insert_and_get_id):", e)
        raise
    finally:
        conn.close()
