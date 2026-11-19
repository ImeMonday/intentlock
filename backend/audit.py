"""Tamper-evident audit trail: each event stores a hash of the previous event."""
import hashlib
import json
from datetime import datetime, timezone


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _hash(prev, ts, typ, data_json):
    return hashlib.sha256(f"{prev}|{ts}|{typ}|{data_json}".encode()).hexdigest()


def add_event(conn, check_id, typ, data):
    last = conn.execute(
        "SELECT seq, hash FROM audit WHERE check_id=? ORDER BY seq DESC LIMIT 1", (check_id,)
    ).fetchone()
    seq = last["seq"] + 1 if last else 1
    prev = last["hash"] if last else "GENESIS"
    ts = now_iso()
    data_json = json.dumps(data, sort_keys=True, default=str)
    h = _hash(prev, ts, typ, data_json)
    conn.execute(
        "INSERT INTO audit(check_id, seq, ts, type, data_json, prev_hash, hash) VALUES (?,?,?,?,?,?,?)",
        (check_id, seq, ts, typ, data_json, prev, h),
    )
    return h


def get_chain(conn, check_id):
    out = []
    for r in conn.execute("SELECT * FROM audit WHERE check_id=? ORDER BY seq", (check_id,)).fetchall():
        out.append(
            {
                "seq": r["seq"],
                "ts": r["ts"],
                "type": r["type"],
                "data": json.loads(r["data_json"]),
                "data_json": r["data_json"],
                "prev_hash": r["prev_hash"],
                "hash": r["hash"],
            }
        )
    return out


def verify_chain(events):
    prev = "GENESIS"
    for e in events:
        if e["prev_hash"] != prev or _hash(prev, e["ts"], e["type"], e["data_json"]) != e["hash"]:
            return False
        prev = e["hash"]
    return True
