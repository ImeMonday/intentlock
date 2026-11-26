"""IntentLock API. Run from the project root:  uvicorn backend.main:app --reload

Every signed-in user has a private vault of receivers and their own check history.
"""
import hashlib
import json
import secrets
import time
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel

from backend import addresses, audit, auth, chain, config, db, extract, llm, rules, signing

app = FastAPI(title="IntentLock")
FRONTEND = Path(__file__).resolve().parent.parent / "frontend"
db.init_db()

COOKIE = "il_session"
OPEN_API = ("/api/auth/", "/api/health", "/api/proof/")
DEMO_NAME, DEMO_DOMAIN = "Global Trade Ltd", "globaltrade.example"
STATUS_OF = {"ok": "approved", "review": "needs_verification", "stop": "withheld"}
RISK_OF = {3: "CRITICAL", 2: "HIGH", 1: "MEDIUM", 0: "LOW"}


def jload(s, default=None):
    try:
        return json.loads(s) if s else default
    except Exception:
        return default


def uid_of(request: Request) -> int:
    uid = getattr(request.state, "uid", None)
    if uid:
        return uid
    with db.get_conn() as conn:
        user = auth.user_for(conn, request.cookies.get(COOKIE))
    if not user:
        raise HTTPException(401, "Please sign in.")
    return user["id"]


# ---------------------------------------------------------------- pages and sign-in
@app.middleware("http")
async def require_login(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/") and not path.startswith(OPEN_API):
        with db.get_conn() as conn:
            user = auth.user_for(conn, request.cookies.get(COOKIE))
        if not user:
            return JSONResponse({"detail": "Please sign in."}, status_code=401)
        request.state.uid = user["id"]
    return await call_next(request)


@app.get("/")
def landing():
    return FileResponse(FRONTEND / "landing.html")


@app.get("/login")
def login_page():
    return FileResponse(FRONTEND / "login.html")


@app.get("/app")
def app_page(request: Request):
    with db.get_conn() as conn:
        if not auth.user_for(conn, request.cookies.get(COOKIE)):
            return RedirectResponse("/login")
    return FileResponse(FRONTEND / "index.html")


@app.get("/proof/{token}")
def proof_page(token: str):
    return FileResponse(FRONTEND / "proof.html")


@app.get("/api/health")
def health():
    return {"ok": True, "llm_enabled": llm.enabled(), "llm_vision": config.LLM_VISION}


class SignupIn(BaseModel):
    email: str
    password: str
    name: str = ""


class LoginIn(BaseModel):
    email: str
    password: str


def _set_cookie(response: Response, token: str):
    response.set_cookie(COOKIE, token, httponly=True, samesite="lax", max_age=60 * 60 * 24 * 7)


@app.post("/api/auth/signup")
def signup(body: SignupIn, response: Response):
    with db.get_conn() as conn:
        try:
            uid = auth.create_user(conn, body.email, body.password, body.name)
        except ValueError as e:
            raise HTTPException(400, str(e))
        token = auth.new_session(conn, uid)
    _set_cookie(response, token)
    return {"ok": True}


@app.post("/api/auth/login")
def login(body: LoginIn, response: Response):
    with db.get_conn() as conn:
        user = auth.check_login(conn, body.email, body.password)
        if not user:
            raise HTTPException(401, "Incorrect email or password.")
        token = auth.new_session(conn, user["id"])
    _set_cookie(response, token)
    return {"ok": True}


@app.post("/api/auth/demo")
def demo_login(response: Response):
    with db.get_conn() as conn:
        token = auth.new_session(conn, auth.demo_user_id(conn))
    _set_cookie(response, token)
    return {"ok": True}


@app.post("/api/auth/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(COOKIE)
    if token:
        with db.get_conn() as conn:
            auth.end_session(conn, token)
    response.delete_cookie(COOKIE)
    return {"ok": True}


@app.get("/api/auth/me")
def me(request: Request):
    with db.get_conn() as conn:
        user = auth.user_for(conn, request.cookies.get(COOKIE))
    if not user:
        raise HTTPException(401, "Please sign in.")
    return user


# ---------------------------------------------------------------- vault (receivers)
def supplier_view(conn, s):
    dests = db.rows(conn, "SELECT id, kind, network, address FROM destinations WHERE supplier_id=? ORDER BY id", (s["id"],))
    has_key = bool(db.one(conn, "SELECT 1 AS x FROM demo_keys WHERE supplier_id=?", (s["id"],)))
    return {"id": s["id"], "name": s["name"], "known_domain": s["known_domain"],
            "signing_address": s["signing_address"], "has_demo_key": has_key, "destinations": dests}


def save_address(conn, uid, name, address, network, known_domain, with_demo_key, via):
    name, address = name.strip(), address.strip()
    if not name or not address:
        raise HTTPException(400, "Enter the receiver's name and address.")
    det = addresses.detect(address)
    net = {"TRON": "TRON", "EVM": "ETHEREUM"}.get(det["family"])
    if not net or not det["valid"]:
        if det["family"] in ("SOLANA", "BITCOIN"):
            raise HTTPException(400, f"This is a {addresses.FAMILY_NAME[det['family']]} address. Cleva accepts USDT on TRON and "
                                     "Ethereum, so save a TRON (T...) or Ethereum (0x...) address.")
        raise HTTPException(400, det["note"] or "Enter a valid TRON (T...) or Ethereum (0x...) address.")
    chosen = chain.norm_network(network) if network else None
    if chosen and chosen != net:
        raise HTTPException(400, f"That is a {addresses.NET_NAME[net]} address, but you selected {addresses.NET_NAME.get(chosen, chosen)}.")
    owner = db.one(conn, "SELECT s.id, s.name FROM destinations d JOIN suppliers s ON s.id = d.supplier_id "
                         "WHERE s.user_id=? AND lower(d.address)=lower(?)", (uid, address))
    sup = db.one(conn, "SELECT * FROM suppliers WHERE user_id=? AND lower(name)=lower(?)", (uid, name))
    if owner and (not sup or owner["id"] != sup["id"]):
        raise HTTPException(409, f"This address is already saved for {owner['name']}.")
    if sup:
        sid = sup["id"]
        if known_domain.strip() and not sup["known_domain"]:
            conn.execute("UPDATE suppliers SET known_domain=? WHERE id=?", (known_domain.strip().lower(), sid))
    else:
        cur = conn.execute("INSERT INTO suppliers(user_id, name, known_domain, created_at) VALUES (?,?,?,?)",
                           (uid, name, known_domain.strip().lower(), audit.now_iso()))
        sid = cur.lastrowid
    if not owner:
        conn.execute("INSERT INTO destinations(supplier_id, kind, network, address, approved_via, created_at) VALUES (?,?,?,?,?,?)",
                     (sid, "wallet", net, address, via, audit.now_iso()))
    if with_demo_key and not db.one(conn, "SELECT 1 AS x FROM demo_keys WHERE supplier_id=?", (sid,)):
        addr, key = signing.new_keypair()
        conn.execute("UPDATE suppliers SET signing_address=? WHERE id=?", (addr, sid))
        conn.execute("INSERT OR REPLACE INTO demo_keys(supplier_id, private_key) VALUES (?,?)", (sid, key))
    return sid


@app.get("/api/suppliers")
def list_suppliers(request: Request):
    uid = uid_of(request)
    with db.get_conn() as conn:
        return [supplier_view(conn, s) for s in db.rows(conn, "SELECT * FROM suppliers WHERE user_id=? ORDER BY id", (uid,))]


class VaultIn(BaseModel):
    name: str
    address: str
    network: str = ""
    known_domain: str = ""
    with_demo_key: bool = False


@app.post("/api/suppliers")
def create_supplier(body: VaultIn, request: Request):
    uid = uid_of(request)
    with db.get_conn() as conn:
        sid = save_address(conn, uid, body.name, body.address, body.network, body.known_domain, body.with_demo_key, "saved by user")
        return supplier_view(conn, db.one(conn, "SELECT * FROM suppliers WHERE id=?", (sid,)))


def _delete_suppliers(conn, ids):
    for sid in ids:
        conn.execute("DELETE FROM destinations WHERE supplier_id=?", (sid,))
        conn.execute("DELETE FROM demo_keys WHERE supplier_id=?", (sid,))
        conn.execute("DELETE FROM suppliers WHERE id=?", (sid,))


@app.delete("/api/suppliers/{sid}")
def remove_supplier(sid: int, request: Request):
    uid = uid_of(request)
    with db.get_conn() as conn:
        if not db.one(conn, "SELECT 1 AS x FROM suppliers WHERE id=? AND user_id=?", (sid, uid)):
            raise HTTPException(404, "Receiver not found.")
        _delete_suppliers(conn, [sid])
    return {"ok": True}


@app.delete("/api/vault")
def clear_vault(request: Request):
    uid = uid_of(request)
    with db.get_conn() as conn:
        _delete_suppliers(conn, [r["id"] for r in db.rows(conn, "SELECT id FROM suppliers WHERE user_id=?", (uid,))])
    return {"ok": True}


@app.get("/api/export")
def export_data(request: Request):
    uid = uid_of(request)
    with db.get_conn() as conn:
        vault = [supplier_view(conn, s) for s in db.rows(conn, "SELECT * FROM suppliers WHERE user_id=? ORDER BY id", (uid,))]
        for v in vault:
            v.pop("signing_address", None)
            v.pop("has_demo_key", None)
        checks = db.rows(conn, "SELECT supplier_name, invoice_number, amount, currency, network, destination, status, risk, created_at "
                               "FROM checks WHERE user_id=? ORDER BY id", (uid,))
    return {"vault": vault, "checks": checks}


# ---------------------------------------------------------------- demo data
@app.post("/api/demo/seed")
def seed(request: Request):
    uid = uid_of(request)
    sha = lambda s: hashlib.sha256(s.encode()).hexdigest()
    gt_tron = chain.tron_address_from_label("intentlock-demo-approved")
    attacker = chain.tron_address_from_label("intentlock-demo-attacker")
    gt_eth = "0x" + sha("intentlock-demo-gt-eth")[:40]
    esther = "0x" + sha("intentlock-demo-eth")[:40]
    look = esther[:6] + sha("intentlock-demo-eth-attacker")[:32] + esther[-4:]
    typo = gt_tron[:20] + ("A" if gt_tron[20] != "A" else "B") + gt_tron[21:]
    with db.get_conn() as conn:
        gt = save_address(conn, uid, DEMO_NAME, gt_tron, "TRON", DEMO_DOMAIN, True, "demo data")
        save_address(conn, uid, DEMO_NAME, gt_eth, "ETHEREUM", "", False, "demo data")
        save_address(conn, uid, "Esther Ltd", esther, "ETHEREUM", "estherltd.example", False, "demo data")

    def sample(domain, wallet, extra=""):
        sender = f"billing@{domain}"
        text = (f"From: {DEMO_NAME} <{sender}>\nInvoice No: INV-2026-001\nDate: 18 November 2026\n"
                f"Bill to: Lagos Imports Ltd\n\n500 units - LED panels\nTotal: 8,000 USDT\n{extra}\n"
                f"Payment details\nNetwork: TRON (TRC20)\nUSDT wallet: {wallet}\n")
        return {"text": text, "sender": sender}

    return {
        "supplier_id": gt,
        "scenarios": {
            "genuine": {"address": gt_tron, "network": "TRON", "supplier_id": gt},
            "wrong_chain": {"address": "So11111111111111111111111111111111111111112", "network": "TRON", "supplier_id": None},
            "poisoned": {"address": look, "network": "ETHEREUM", "supplier_id": None},
            "typo": {"address": typo, "network": "TRON", "supplier_id": gt},
            "changed": {"address": attacker, "network": "TRON", "supplier_id": gt},
            "token": {"address": config.TRON_USDT, "network": "TRON", "supplier_id": None},
        },
        "samples": {
            "a": sample(DEMO_DOMAIN, gt_tron, "Thank you for your business."),
            "b": sample("g1obaltrade.example", attacker,
                        "URGENT: we have changed our wallet. Use the new wallet below and do not call, we are in a meeting."),
        },
    }


class SignIn(BaseModel):
    supplier_id: int
    text: str
    hours_valid: int = 72


@app.post("/api/demo/sign")
def demo_sign(body: SignIn, request: Request):
    uid = uid_of(request)
    with db.get_conn() as conn:
        sup = db.one(conn, "SELECT * FROM suppliers WHERE id=? AND user_id=?", (body.supplier_id, uid))
        key = db.one(conn, "SELECT private_key FROM demo_keys WHERE supplier_id=?", (body.supplier_id,))
    if not sup or not key:
        raise HTTPException(400, "This receiver has no demo signing key. Load the demo data first.")
    ex = extract.heuristic_extract(body.text)
    if not ex["destination"] or not ex["amount"]:
        raise HTTPException(400, "Could not find an amount and destination in the invoice text to sign.")
    net = ex["network"] or "TRON"
    token = chain.official_token(net) if ex["dest_kind"] == "wallet" else "USD"
    msg = signing.build_message(sup["name"], ex["invoice_number"], ex["amount"], token, net,
                                ex["destination"], time.time() + body.hours_valid * 3600)
    return {"message": msg, "signature": signing.sign_message(msg, key["private_key"]), "signer": sup["signing_address"]}


# ---------------------------------------------------------------- checks
def check_view(conn, check_id, uid=None):
    c = db.one(conn, "SELECT * FROM checks WHERE id=?", (check_id,))
    if not c or (uid is not None and c["user_id"] != uid):
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
        "settlement": jload(c["settlement_json"], None), "registered": registered,
        "audit": events, "audit_ok": audit.verify_chain(events),
    }


def insert_check(conn, uid, supplier_id, supplier_name, invoice_number, amount, currency, network, destination, dest_kind,
                 sender_domain, status, risk, findings, extracted, explanation, signed_json=None):
    cur = conn.execute(
        "INSERT INTO checks(token, user_id, supplier_id, supplier_name, invoice_number, amount, currency, network, destination, "
        "dest_kind, sender_domain, status, risk, findings_json, extracted_json, explanation, signed_json, created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (secrets.token_urlsafe(9), uid, supplier_id, supplier_name, invoice_number, amount, currency, network, destination,
         dest_kind, sender_domain, status, risk, json.dumps(findings), json.dumps(extracted), explanation, signed_json, audit.now_iso()))
    return cur.lastrowid


def _known_addresses(conn, uid):
    saved = [r["address"] for r in db.rows(conn, "SELECT d.address FROM destinations d JOIN suppliers s ON s.id = d.supplier_id WHERE s.user_id=?", (uid,))]
    seen = [r["destination"] for r in db.rows(conn, "SELECT DISTINCT destination FROM checks WHERE user_id=? AND dest_kind='wallet' AND destination IS NOT NULL", (uid,))]
    return saved + seen


class AddressIn(BaseModel):
    address: str
    network: str = ""
    supplier_id: Optional[int] = None
    asset: str = "USDT"


@app.post("/api/address/check")
def address_check(body: AddressIn, request: Request):
    uid = uid_of(request)
    addr = body.address.strip()
    if not addr:
        raise HTTPException(400, "Paste an address to check.")
    net = chain.norm_network(body.network) if body.network else None
    with db.get_conn() as conn:
        saved = db.rows(conn, "SELECT d.address, d.network, s.id AS sid, s.name FROM destinations d "
                              "JOIN suppliers s ON s.id = d.supplier_id WHERE s.user_id=?", (uid,))
        chosen = None
        if body.supplier_id:
            chosen = db.one(conn, "SELECT * FROM suppliers WHERE id=? AND user_id=?", (body.supplier_id, uid))
            if not chosen:
                raise HTTPException(404, "Receiver not found.")
        findings = addresses.preflight(addr, net, body.asset or "USDT")
        vault_f, match = addresses.vault_check(addr, saved, chosen["id"] if chosen else None, chosen["name"] if chosen else None)
        findings += vault_f
        if not any(f["id"] == "ADDRESS_TYPO" for f in vault_f):
            findings += addresses.poison_findings(addr, _known_addresses(conn, uid))
        worst = max((rules.RANK[f["severity"]] for f in findings), default=0)
        verdict = "stop" if worst >= 3 else "review" if worst >= 1 else "ok"
        det = addresses.detect(addr)
        shown_net = net or addresses.DEFAULT_NET.get(det["family"])
        name = match["name"] if match else (chosen["name"] if chosen else "Unsaved address")
        if verdict == "ok":
            explanation = f"Valid address on {addresses.NET_NAME.get(shown_net, shown_net)}" + (f", saved for {name}." if match else ".")
        else:
            issues = [f["title"] for f in findings if rules.RANK[f["severity"]] >= 1]
            explanation = ("Do not send. " if verdict == "stop" else "Check before sending. ") + "; ".join(issues[:3]) + "."
        cid = insert_check(conn, uid, match["sid"] if match else (chosen["id"] if chosen else None), name, None, None, "USDT",
                           shown_net, addr, "wallet", "", STATUS_OF[verdict], RISK_OF[worst], findings,
                           {"extraction_method": "Address check"}, explanation)
        audit.add_event(conn, cid, "address_checked", {"verdict": verdict, "findings": [f["id"] for f in findings]})
        view = check_view(conn, cid, uid)
    view.update(verdict=verdict, saved_match=match["name"] if match else None, detected=det,
                can_save=bool(match is None and worst < 3 and det["valid"]))
    return view


def resolve_supplier(conn, uid, supplier_id, text, name):
    if supplier_id.strip().isdigit():
        s = db.one(conn, "SELECT * FROM suppliers WHERE id=? AND user_id=?", (int(supplier_id), uid))
        if s:
            return s
    low = (text or "").lower()
    for s in db.rows(conn, "SELECT * FROM suppliers WHERE user_id=?", (uid,)):
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
        sig["reason"] = "This receiver has no registered signing key."
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
def analyze(request: Request, supplier_id: str = Form(""), sender: str = Form(""), text: str = Form(""),
            signed_json: str = Form(""), file: Optional[UploadFile] = File(None)):
    uid = uid_of(request)
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
        supplier = resolve_supplier(conn, uid, supplier_id, text, ex.get("supplier_name"))
        dests, hist = [], []
        if supplier:
            dests = db.rows(conn, "SELECT kind, network, address FROM destinations WHERE supplier_id=?", (supplier["id"],))
            hist = db.rows(conn, "SELECT amount, invoice_number, destination, settlement_json FROM checks "
                                 "WHERE supplier_id=? AND user_id=? AND status!='rejected' AND invoice_number IS NOT NULL ORDER BY id",
                           (supplier["id"], uid))
            for h in hist:
                h["paid"] = (jload(h["settlement_json"], {}) or {}).get("status") == "VERIFIED"
        email = (sender or ex.get("sender_email") or "").strip().lower()
        domain = email.split("@")[-1] if email else ""
        sig = build_sig(conn, supplier, signed_json)

        known = _known_addresses(conn, uid)
        findings = rules.evaluate(ex, supplier, dests, hist, domain, text, sig, known)
        status, risk = rules.decide(findings)
        explanation = rules.template_explanation(status, findings)
        if llm.enabled():
            try:
                explanation = llm.explain(status, findings)
            except Exception:
                pass

        ex["extraction_method"] = method
        sname = supplier["name"] if supplier else (ex.get("supplier_name") or "Unknown supplier")
        cid = insert_check(conn, uid, supplier["id"] if supplier else None, sname, ex.get("invoice_number"), ex.get("amount"),
                           ex.get("currency"), ex.get("network"), ex.get("destination"), ex.get("dest_kind"), domain,
                           status, risk, findings, ex, explanation, signed_json or None)
        audit.add_event(conn, cid, "invoice_received", {"extracted": ex, "supplier_matched": bool(supplier)})
        audit.add_event(conn, cid, "risk_assessed", {"status": status, "risk": risk, "findings": [f["id"] for f in findings]})
        return check_view(conn, cid, uid)


@app.get("/api/checks")
def list_checks(request: Request):
    uid = uid_of(request)
    with db.get_conn() as conn:
        return db.rows(conn, "SELECT id, token, supplier_name, invoice_number, amount, currency, destination, status, risk, created_at "
                             "FROM checks WHERE user_id=? ORDER BY id DESC LIMIT 50", (uid,))


@app.get("/api/checks/{cid}")
def get_check(cid: int, request: Request):
    uid = uid_of(request)
    with db.get_conn() as conn:
        return check_view(conn, cid, uid)


def _own_check(conn, cid, uid):
    c = db.one(conn, "SELECT * FROM checks WHERE id=? AND user_id=?", (cid, uid))
    if not c:
        raise HTTPException(404, "Check not found.")
    return c


class ConfirmIn(BaseModel):
    method: str
    confirmed_by: str
    note: str = ""
    add_to_approved: bool = False


@app.post("/api/checks/{cid}/confirm")
def confirm(cid: int, body: ConfirmIn, request: Request):
    uid = uid_of(request)
    if body.method not in ("callback", "second_approver", "supplier_channel"):
        raise HTTPException(400, "Unknown confirmation method.")
    if not body.confirmed_by.strip():
        raise HTTPException(400, "Enter who confirmed this.")
    with db.get_conn() as conn:
        c = _own_check(conn, cid, uid)
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
                sid = save_address(conn, uid, name, c["destination"], c["network"], c["sender_domain"] or "", False, f"out-of-band: {body.method}")
                conn.execute("UPDATE checks SET supplier_id=? WHERE id=?", (sid, cid))
            else:
                conn.execute("INSERT INTO destinations(supplier_id, kind, network, address, approved_via, created_at) VALUES (?,?,?,?,?,?)",
                             (sid, "wallet", c["network"], c["destination"], f"out-of-band: {body.method}", audit.now_iso()))
            added = True
        audit.add_event(conn, cid, "out_of_band_confirmation",
                        {"method": body.method, "confirmed_by": body.confirmed_by.strip(), "note": body.note.strip(),
                         "added_to_approved_list": added})
        return check_view(conn, cid, uid)


@app.post("/api/checks/{cid}/reject")
def reject(cid: int, request: Request):
    uid = uid_of(request)
    with db.get_conn() as conn:
        _own_check(conn, cid, uid)
        conn.execute("UPDATE checks SET status='rejected' WHERE id=?", (cid,))
        audit.add_event(conn, cid, "rejected_by_owner", {})
        return check_view(conn, cid, uid)


@app.post("/api/checks/{cid}/use-verified")
def use_verified(cid: int, request: Request):
    uid = uid_of(request)
    with db.get_conn() as conn:
        c = _own_check(conn, cid, uid)
        if c["status"] not in ("needs_verification", "withheld"):
            raise HTTPException(400, "Nothing to swap on this check.")
        reg = None
        if c["supplier_id"]:
            reg = db.one(conn, "SELECT network, address FROM destinations WHERE supplier_id=? AND kind='wallet' ORDER BY id LIMIT 1",
                         (c["supplier_id"],))
        if not reg:
            raise HTTPException(400, "This receiver has no saved wallet to swap to.")
        findings = jload(c["findings_json"], [])
        findings.append({"id": "SWAPPED_TO_VERIFIED", "severity": "info", "blocking": False,
                         "title": "Paying the receiver's saved wallet",
                         "detail": f"The invoice destination was replaced with the saved wallet {chain.short(reg['address'])}."})
        conn.execute("UPDATE checks SET destination=?, network=?, dest_kind='wallet', status='approved_swapped', findings_json=? WHERE id=?",
                     (reg["address"], reg["network"], json.dumps(findings), cid))
        audit.add_event(conn, cid, "swapped_to_verified_wallet", {"from": c["destination"], "to": reg["address"]})
        return check_view(conn, cid, uid)


class SettleIn(BaseModel):
    txid: str
    network: Optional[str] = None


@app.post("/api/checks/{cid}/settle")
def settle(cid: int, body: SettleIn, request: Request):
    uid = uid_of(request)
    with db.get_conn() as conn:
        c = _own_check(conn, cid, uid)
    net = chain.norm_network(body.network or c["network"])
    if c["dest_kind"] != "wallet" or net not in ("TRON", "ETHEREUM"):
        raise HTTPException(400, "On-chain verification applies to TRON or Ethereum wallet payments only.")
    if c["amount"] is None:
        raise HTTPException(400, "Run an invoice check first so there is an amount to verify against.")
    try:
        result = chain.verify_settlement(net, body.txid, c["destination"], c["amount"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    except (httpx.HTTPError, RuntimeError) as e:
        raise HTTPException(502, f"Could not reach the blockchain data service ({e.__class__.__name__}). Try again.")
    if c["status"] not in ("approved", "approved_verified", "approved_swapped"):
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
        return check_view(conn, cid, uid)


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
