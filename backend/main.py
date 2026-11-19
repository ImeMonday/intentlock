"""IntentLock API. Run from the project root:  uvicorn backend.main:app --reload"""
import json
import secrets
import time
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel

from backend import audit, chain, config, db, extract, llm, rules, signing

app = FastAPI(title="IntentLock")
FRONTEND = Path(__file__).resolve().parent.parent / "frontend"
db.init_db()

DEMO_NAME = "Global Trade Ltd"
DEMO_DOMAIN = "globaltrade.example"


def jload(s, default=None):
    try:
        return json.loads(s) if s else default
    except Exception:
        return default


# ---------------------------------------------------------------- pages
@app.get("/")
def home():
    return FileResponse(FRONTEND / "index.html")


@app.get("/proof/{token}")
def proof_page(token: str):
    return FileResponse(FRONTEND / "proof.html")


@app.get("/api/health")
def health():
    return {"ok": True, "llm_enabled": llm.enabled(), "llm_vision": config.LLM_VISION}


# ---------------------------------------------------------------- suppliers
def supplier_view(conn, s):
    dests = db.rows(conn, "SELECT kind, network, address, approved_via FROM destinations WHERE supplier_id=? ORDER BY id", (s["id"],))
    has_key = bool(db.one(conn, "SELECT 1 AS x FROM demo_keys WHERE supplier_id=?", (s["id"],)))
    return {"id": s["id"], "name": s["name"], "known_domain": s["known_domain"],
            "signing_address": s["signing_address"], "has_demo_key": has_key, "destinations": dests}


def add_supplier(conn, name, destination, known_domain, with_demo_key, via):
    name, destination = name.strip(), destination.strip()
    if not name or not destination:
        raise HTTPException(400, "Name and destination are required.")
    net = chain.guess_network(destination)
    if not net or not chain.is_valid_address(net, destination):
        raise HTTPException(400, "Destination must be a valid TRON (T...) or Ethereum (0x...) address.")
    if db.one(conn, "SELECT 1 AS x FROM suppliers WHERE name=?", (name,)):
        raise HTTPException(409, "A supplier with this name already exists.")
    cur = conn.execute("INSERT INTO suppliers(name, known_domain, created_at) VALUES (?,?,?)",
                       (name, known_domain.strip().lower(), audit.now_iso()))
    sid = cur.lastrowid
    conn.execute("INSERT INTO destinations(supplier_id, kind, network, address, approved_via, created_at) VALUES (?,?,?,?,?,?)",
                 (sid, "wallet", net, destination, via, audit.now_iso()))
    if with_demo_key:
        addr, key = signing.new_keypair()
        conn.execute("UPDATE suppliers SET signing_address=? WHERE id=?", (addr, sid))
        conn.execute("INSERT OR REPLACE INTO demo_keys(supplier_id, private_key) VALUES (?,?)", (sid, key))
    return sid


@app.get("/api/suppliers")
def list_suppliers():
    with db.get_conn() as conn:
        return [supplier_view(conn, s) for s in db.rows(conn, "SELECT * FROM suppliers ORDER BY id")]


class SupplierIn(BaseModel):
    name: str
    destination: str
    known_domain: str = ""
    with_demo_key: bool = False


@app.post("/api/suppliers")
def create_supplier(body: SupplierIn):
    with db.get_conn() as conn:
        sid = add_supplier(conn, body.name, body.destination, body.known_domain, body.with_demo_key, "initial enrolment")
        return supplier_view(conn, db.one(conn, "SELECT * FROM suppliers WHERE id=?", (sid,)))


# ---------------------------------------------------------------- demo helpers
@app.post("/api/demo/seed")
def seed():
    approved = chain.tron_address_from_label("intentlock-demo-approved")
    attacker = chain.tron_address_from_label("intentlock-demo-attacker")
    with db.get_conn() as conn:
        s = db.one(conn, "SELECT id FROM suppliers WHERE name=?", (DEMO_NAME,))
        if not s:
            add_supplier(conn, DEMO_NAME, approved, DEMO_DOMAIN, True, "demo seed")
            s = db.one(conn, "SELECT id FROM suppliers WHERE name=?", (DEMO_NAME,))
    # If you edited the demo supplier's wallet, samples still use the original demo addresses.

    def sample(domain, wallet, extra=""):
        sender = f"billing@{domain}"
        text = (f"From: {DEMO_NAME} <{sender}>\nInvoice No: INV-2026-001\nDate: 18 November 2026\n"
                f"Bill to: Lagos Imports Ltd\n\n500 units - LED panels\nTotal: 8,000 USDT\n{extra}\n"
                f"Payment details\nNetwork: TRON (TRC20)\nUSDT wallet: {wallet}\n")
        return {"text": text, "sender": sender}

    return {
        "supplier_id": s["id"],
        "samples": {
            "a": sample(DEMO_DOMAIN, approved, "Thank you for your business."),
            "b": sample("g1obaltrade.example", attacker,
                        "URGENT: we have changed our wallet. Use the new wallet below and do not call, we are in a meeting."),
        },
    }


class SignIn(BaseModel):
    supplier_id: int
    text: str
    hours_valid: int = 72


@app.post("/api/demo/sign")
def demo_sign(body: SignIn):
    with db.get_conn() as conn:
        sup = db.one(conn, "SELECT * FROM suppliers WHERE id=?", (body.supplier_id,))
        key = db.one(conn, "SELECT private_key FROM demo_keys WHERE supplier_id=?", (body.supplier_id,))
    if not sup or not key:
        raise HTTPException(400, "This supplier has no demo signing key. Add it with the demo signing key option.")
    ex = extract.heuristic_extract(body.text)
    if not ex["destination"] or not ex["amount"]:
        raise HTTPException(400, "Could not find an amount and destination in the invoice text to sign.")
    net = ex["network"] or "TRON"
    token = chain.official_token(net) if ex["dest_kind"] == "wallet" else "USD"
    msg = signing.build_message(sup["name"], ex["invoice_number"], ex["amount"], token, net,
                                ex["destination"], time.time() + body.hours_valid * 3600)
    return {"message": msg, "signature": signing.sign_message(msg, key["private_key"]), "signer": sup["signing_address"]}


# ---------------------------------------------------------------- checks
def check_view(conn, check_id):
    c = db.one(conn, "SELECT * FROM checks WHERE id=?", (check_id,))
    if not c:
        raise HTTPException(404, "Check not found.")
    events = audit.get_chain(conn, check_id)
    registered = []
    if c["supplier_id"]:
        registered = db.rows(conn, "SELECT network, address FROM destinations WHERE supplier_id=? AND kind='wallet' ORDER BY id", (c["supplier_id"],))
    return {
        "id": c["id"], "token": c["token"], "supplier_id": c["supplier_id"], "supplier_name": c["supplier_name"],
        "invoice_number": c["invoice_number"], "amount": c["amount"], "currency": c["currency"],
        "network": c["network"], "destination": c["destination"], "dest_kind": c["dest_kind"],
        "sender_domain": c["sender_domain"], "status": c["status"], "risk": c["risk"],
        "explanation": c["explanation"], "created_at": c["created_at"],
        "findings": jload(c["findings_json"], []), "extracted": jload(c["extracted_json"], {}),
        "settlement": jload(c["settlement_json"], None),
        "registered": registered,
        "audit": events, "audit_ok": audit.verify_chain(events),
    }


def resolve_supplier(conn, supplier_id, text, name):
    if supplier_id.strip().isdigit():
        s = db.one(conn, "SELECT * FROM suppliers WHERE id=?", (int(supplier_id),))
        if s:
            return s
    low = (text or "").lower()
    for s in db.rows(conn, "SELECT * FROM suppliers"):
        if s["name"].lower() in low or (name and name.lower() == s["name"].lower()):
            return s
    return None


def build_sig(conn, supplier, signed_json):
    if not signed_json.strip():
        return None
    sig = {"present": True, "valid": False, "reason": "", "message": None, "expired": False, "replay": False}
    try:
        signed = json.loads(signed_json)
    except Exception:
        sig["reason"] = "The signed instruction is not valid JSON."
        return sig
    if not supplier or not supplier.get("signing_address"):
        sig["reason"] = "This supplier has no registered signing key."
        return sig
    ok, reason, msg = signing.verify_instruction(signed, supplier["signing_address"])
    sig.update(valid=ok, reason=reason, message=msg)
    if ok and msg:
        try:
            sig["expired"] = int(msg.get("expiry", 0)) < int(time.time())
        except Exception:
            sig["expired"] = True
        if db.one(conn, "SELECT 1 AS x FROM nonces WHERE nonce=?", (str(msg.get("nonce")),)):
            sig["replay"] = True
    return sig


@app.post("/api/analyze")
def analyze(supplier_id: str = Form(""), sender: str = Form(""), text: str = Form(""),
            signed_json: str = Form(""), file: Optional[UploadFile] = File(None)):
    text = text.strip()
    image = None
    if file and file.filename:
        data = file.file.read()
        name = file.filename.lower()
        try:
            if name.endswith(".pdf"):
                text = (text + "\n" + extract.pdf_to_text(data)).strip()
            elif name.endswith((".png", ".jpg", ".jpeg", ".webp")):
                mime = "image/png" if name.endswith(".png") else "image/webp" if name.endswith(".webp") else "image/jpeg"
                image = (data, mime)
            else:
                text = (text + "\n" + data.decode("utf-8", errors="ignore")).strip()
        except Exception as e:
            raise HTTPException(400, f"Could not read the file ({e.__class__.__name__}). Paste the invoice text instead.")
    if not text and not image:
        raise HTTPException(400, "Paste invoice or message text, or upload a PDF.")
    try:
        ex, method = extract.extract_fields(text, image)
    except ValueError as e:
        raise HTTPException(400, str(e))

    with db.get_conn() as conn:
        supplier = resolve_supplier(conn, supplier_id, text, ex.get("supplier_name"))
        dests, hist = [], []
        if supplier:
            dests = db.rows(conn, "SELECT kind, network, address FROM destinations WHERE supplier_id=?", (supplier["id"],))
            hist = db.rows(conn, "SELECT amount, invoice_number, destination, settlement_json FROM checks "
                                 "WHERE supplier_id=? AND status!='rejected' ORDER BY id", (supplier["id"],))
            for h in hist:
                h["paid"] = (jload(h["settlement_json"], {}) or {}).get("status") == "VERIFIED"
        email = (sender or ex.get("sender_email") or "").strip().lower()
        domain = email.split("@")[-1] if email else ""
        sig = build_sig(conn, supplier, signed_json)

        findings = rules.evaluate(ex, supplier, dests, hist, domain, text, sig)
        status, risk = rules.decide(findings)
        explanation = rules.template_explanation(status, findings)
        if llm.enabled():
            try:
                explanation = llm.explain(status, findings)
            except Exception:
                pass

        ex["extraction_method"] = method
        sname = supplier["name"] if supplier else (ex.get("supplier_name") or "Unknown supplier")
        cur = conn.execute(
            "INSERT INTO checks(token, supplier_id, supplier_name, invoice_number, amount, currency, network, destination, "
            "dest_kind, sender_domain, status, risk, findings_json, extracted_json, explanation, signed_json, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (secrets.token_urlsafe(9), supplier["id"] if supplier else None, sname, ex.get("invoice_number"),
             ex.get("amount"), ex.get("currency"), ex.get("network"), ex.get("destination"), ex.get("dest_kind"),
             domain, status, risk, json.dumps(findings), json.dumps(ex), explanation, signed_json or None, audit.now_iso()))
        cid = cur.lastrowid
        audit.add_event(conn, cid, "invoice_received", {"extracted": ex, "supplier_matched": bool(supplier)})
        audit.add_event(conn, cid, "risk_assessed", {"status": status, "risk": risk, "findings": [f["id"] for f in findings]})
        return check_view(conn, cid)


@app.get("/api/checks")
def list_checks():
    with db.get_conn() as conn:
        return db.rows(conn, "SELECT id, token, supplier_name, invoice_number, amount, currency, status, risk, created_at "
                             "FROM checks ORDER BY id DESC LIMIT 50")


@app.get("/api/checks/{cid}")
def get_check(cid: int):
    with db.get_conn() as conn:
        return check_view(conn, cid)


class ConfirmIn(BaseModel):
    method: str
    confirmed_by: str
    note: str = ""
    add_to_approved: bool = False


@app.post("/api/checks/{cid}/confirm")
def confirm(cid: int, body: ConfirmIn):
    if body.method not in ("callback", "second_approver", "supplier_channel"):
        raise HTTPException(400, "Unknown confirmation method.")
    if not body.confirmed_by.strip():
        raise HTTPException(400, "Enter who confirmed this.")
    with db.get_conn() as conn:
        c = db.one(conn, "SELECT * FROM checks WHERE id=?", (cid,))
        if not c:
            raise HTTPException(404, "Check not found.")
        if c["status"] not in ("needs_verification", "withheld"):
            raise HTTPException(400, "This check does not need confirmation.")
        if any(f.get("blocking") for f in jload(c["findings_json"], [])):
            raise HTTPException(400, "This invoice has a blocking problem (no valid destination). It cannot be approved.")
        conn.execute("UPDATE checks SET status='approved_verified' WHERE id=?", (cid,))
        added = False
        if body.add_to_approved and c["dest_kind"] == "wallet":
            sid = c["supplier_id"]
            if not sid:
                name = c["supplier_name"] if c["supplier_name"] != "Unknown supplier" else f"Unnamed supplier {cid}"
                conn.execute("INSERT OR IGNORE INTO suppliers(name, known_domain, created_at) VALUES (?,?,?)",
                             (name, c["sender_domain"] or "", audit.now_iso()))
                sid = db.one(conn, "SELECT id FROM suppliers WHERE name=?", (name,))["id"]
                conn.execute("UPDATE checks SET supplier_id=? WHERE id=?", (sid, cid))
            conn.execute("INSERT INTO destinations(supplier_id, kind, network, address, approved_via, created_at) VALUES (?,?,?,?,?,?)",
                         (sid, "wallet", c["network"], c["destination"], f"out-of-band: {body.method}", audit.now_iso()))
            added = True
        audit.add_event(conn, cid, "out_of_band_confirmation",
                        {"method": body.method, "confirmed_by": body.confirmed_by.strip(), "note": body.note.strip(),
                         "added_to_approved_list": added})
        return check_view(conn, cid)


@app.post("/api/checks/{cid}/reject")
def reject(cid: int):
    with db.get_conn() as conn:
        if not db.one(conn, "SELECT 1 AS x FROM checks WHERE id=?", (cid,)):
            raise HTTPException(404, "Check not found.")
        conn.execute("UPDATE checks SET status='rejected' WHERE id=?", (cid,))
        audit.add_event(conn, cid, "rejected_by_owner", {})
        return check_view(conn, cid)


@app.post("/api/checks/{cid}/use-verified")
def use_verified(cid: int):
    with db.get_conn() as conn:
        c = db.one(conn, "SELECT * FROM checks WHERE id=?", (cid,))
        if not c:
            raise HTTPException(404, "Check not found.")
        if c["status"] not in ("needs_verification", "withheld"):
            raise HTTPException(400, "Nothing to swap on this check.")
        reg = None
        if c["supplier_id"]:
            reg = db.one(conn, "SELECT network, address FROM destinations WHERE supplier_id=? AND kind='wallet' ORDER BY id LIMIT 1",
                         (c["supplier_id"],))
        if not reg:
            raise HTTPException(400, "This supplier has no registered wallet to swap to.")
        findings = jload(c["findings_json"], [])
        findings.append({"id": "SWAPPED_TO_VERIFIED", "severity": "info", "blocking": False,
                         "title": "Paying the supplier's registered wallet",
                         "detail": f"The invoice destination was replaced with the registered wallet {chain.short(reg['address'])}."})
        conn.execute("UPDATE checks SET destination=?, network=?, dest_kind='wallet', status='approved_swapped', findings_json=? WHERE id=?",
                     (reg["address"], reg["network"], json.dumps(findings), cid))
        audit.add_event(conn, cid, "swapped_to_verified_wallet", {"from": c["destination"], "to": reg["address"]})
        return check_view(conn, cid)


class SettleIn(BaseModel):
    txid: str
    network: Optional[str] = None


@app.post("/api/checks/{cid}/settle")
def settle(cid: int, body: SettleIn):
    with db.get_conn() as conn:
        c = db.one(conn, "SELECT * FROM checks WHERE id=?", (cid,))
        if not c:
            raise HTTPException(404, "Check not found.")
    net = chain.norm_network(body.network or c["network"])
    if c["dest_kind"] != "wallet" or net not in ("TRON", "ETHEREUM"):
        raise HTTPException(400, "On-chain verification applies to TRON or Ethereum wallet payments only.")
    try:
        result = chain.verify_settlement(net, body.txid, c["destination"], c["amount"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    except (httpx.HTTPError, RuntimeError) as e:
        raise HTTPException(502, f"Could not reach the blockchain data service ({e.__class__.__name__}). Try again.")
    approved = c["status"] in ("approved", "approved_verified", "approved_swapped")
    if not approved:
        result["findings"].append({"severity": "high", "title": "Paid without approval",
                                   "detail": "This payment was not approved in IntentLock before it was sent."})
    with db.get_conn() as conn:
        conn.execute("UPDATE checks SET settlement_json=? WHERE id=?", (json.dumps(result), cid))
        audit.add_event(conn, cid, "settlement_verified",
                        {"status": result["status"], "txid": result["txid"], "simulated": result["simulated"],
                         "received": result["received"], "confirmations": result["confirmations"]})
        if result["status"] == "VERIFIED" and c["signed_json"]:
            nonce = ((jload(c["signed_json"], {}) or {}).get("message") or {}).get("nonce")
            if nonce:
                conn.execute("INSERT OR IGNORE INTO nonces(nonce, check_id, created_at) VALUES (?,?,?)",
                             (str(nonce), cid, audit.now_iso()))
        return check_view(conn, cid)


@app.get("/api/proof/{token}")
def proof(token: str):
    with db.get_conn() as conn:
        c = db.one(conn, "SELECT id FROM checks WHERE token=?", (token,))
        if not c:
            raise HTTPException(404, "Proof not found.")
        v = check_view(conn, c["id"])
    v.pop("id", None)
    v.pop("supplier_id", None)
    return v
