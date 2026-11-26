"""Tiny SQLite layer (standard library only)."""
import sqlite3
from contextlib import contextmanager

from backend import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS suppliers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  name TEXT NOT NULL,
  known_domain TEXT DEFAULT '',
  signing_address TEXT DEFAULT '',
  created_at TEXT
);
CREATE TABLE IF NOT EXISTS destinations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  supplier_id INTEGER NOT NULL,
  kind TEXT NOT NULL,
  network TEXT NOT NULL,
  address TEXT NOT NULL,
  approved_via TEXT,
  created_at TEXT
);
CREATE TABLE IF NOT EXISTS checks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token TEXT UNIQUE NOT NULL,
  user_id INTEGER,
  supplier_id INTEGER,
  supplier_name TEXT,
  invoice_number TEXT,
  amount REAL,
  currency TEXT,
  network TEXT,
  destination TEXT,
  dest_kind TEXT,
  sender_domain TEXT,
  status TEXT,
  risk TEXT,
  findings_json TEXT,
  extracted_json TEXT,
  explanation TEXT,
  signed_json TEXT,
  settlement_json TEXT,
  created_at TEXT
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  check_id INTEGER NOT NULL,
  seq INTEGER NOT NULL,
  ts TEXT NOT NULL,
  type TEXT NOT NULL,
  data_json TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS nonces (
  nonce TEXT PRIMARY KEY,
  check_id INTEGER,
  created_at TEXT
);
CREATE TABLE IF NOT EXISTS demo_keys (
  supplier_id INTEGER PRIMARY KEY,
  private_key TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  name TEXT,
  pw_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  created_at TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  created_at TEXT
);
"""


@contextmanager
def get_conn():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(suppliers)").fetchall()]
        if cols and "user_id" not in cols:  # old shared-workspace schema: reset the data tables (accounts are kept)
            conn.executescript("DROP TABLE IF EXISTS suppliers; DROP TABLE IF EXISTS destinations; DROP TABLE IF EXISTS checks; "
                               "DROP TABLE IF EXISTS audit; DROP TABLE IF EXISTS nonces; DROP TABLE IF EXISTS demo_keys;")
        conn.executescript(SCHEMA)


def rows(conn, sql, params=()):
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def one(conn, sql, params=()):
    r = conn.execute(sql, params).fetchone()
    return dict(r) if r else None
