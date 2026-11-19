"""Address checks and on-chain verification of USDT payments (TRON and Ethereum).

Verification uses public chain data only. IntentLock never holds keys or funds.
Hashes starting with DEMO (for example DEMO-REAL) return SIMULATED results for rehearsal.
"""
import hashlib
import re
from decimal import Decimal

import httpx
from eth_utils import is_address

from backend import config

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


# ---------- base58 / TRON addresses ----------
def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    s = ""
    while n > 0:
        n, r = divmod(n, 58)
        s = B58[r] + s
    pad = len(b) - len(b.lstrip(b"\0"))
    return "1" * pad + s


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        i = B58.find(ch)
        if i < 0:
            raise ValueError("bad base58 character")
        n = n * 58 + i
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\0" * pad + raw


def _checksum(payload: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]


def tron_is_valid(addr: str) -> bool:
    try:
        raw = b58decode((addr or "").strip())
    except ValueError:
        return False
    if len(raw) != 25 or raw[0] != 0x41:
        return False
    return _checksum(raw[:-4]) == raw[-4:]


def tron_from_hex(h: str) -> str:
    h = str(h).lower()
    if h.startswith("0x"):
        h = h[2:]
    if len(h) == 40:
        h = "41" + h
    payload = bytes.fromhex(h)
    return b58encode(payload + _checksum(payload))


def tron_address_from_label(label: str) -> str:
    """Deterministic, well-formed demo address (not a real wallet)."""
    return tron_from_hex(hashlib.sha256(label.encode()).hexdigest()[:40])


def _to_tron(v) -> str:
    v = str(v)
    if v.startswith("T") and len(v) == 34:
        return v
    try:
        return tron_from_hex(v)
    except Exception:
        return v


# ---------- generic helpers ----------
def norm_network(n):
    s = (n or "").strip().upper().replace("-", "").replace(" ", "")
    if s in ("TRON", "TRC20", "TRX"):
        return "TRON"
    if s in ("ETHEREUM", "ERC20", "ETH"):
        return "ETHEREUM"
    if s == "BANK":
        return "BANK"
    return s or None


def guess_network(addr):
    a = (addr or "").strip()
    if a.startswith("0x") and len(a) == 42:
        return "ETHEREUM"
    if a.startswith("T") and len(a) == 34:
        return "TRON"
    return None


def is_valid_address(network, addr) -> bool:
    a = (addr or "").strip()
    if network == "TRON":
        return tron_is_valid(a)
    if network == "ETHEREUM":
        try:
            return a.startswith("0x") and len(a) == 42 and bool(is_address(a))
        except Exception:
            return False
    return False


def same_address(network, a, b) -> bool:
    a, b = (a or "").strip(), (b or "").strip()
    if network == "ETHEREUM":
        return a.lower() == b.lower()
    return a == b


def official_token(network) -> str:
    if network == "TRON":
        return config.TRON_USDT
    if network == "ETHEREUM":
        return config.ETH_USDT
    return "USD"


def short(addr) -> str:
    a = addr or ""
    return a if len(a) <= 14 else a[:6] + "…" + a[-4:]


# ---------- judging a settlement (pure logic, no network) ----------
def _f(sev, title, detail):
    return {"severity": sev, "title": title, "detail": detail}


def evaluate_settlement(network, transfers, confirmations, expected_dest, expected_amount):
    findings = []
    to_dest = [t for t in transfers if same_address(network, t["to"], expected_dest)]
    received = 0.0
    status = "VERIFIED"
    if not to_dest:
        status = "MISMATCH"
        where = ", ".join(sorted({short(t["to"]) for t in transfers})) or "nowhere we could see"
        findings.append(_f("critical", "Funds did not go to the approved destination",
                           f"The transaction paid {where}, not {short(expected_dest)}."))
    else:
        real = [t for t in to_dest if t["official"]]
        if not real:
            status = "FAKE_TOKEN"
            findings.append(_f("critical", "Not genuine USDT",
                               "A token arrived at this address, but its contract is not the official Tether USDT contract. "
                               "It may be a lookalike token with no real value."))
        else:
            received = float(sum(Decimal(str(t["amount"])) for t in real))
            findings.append(_f("info", "Genuine USDT received at the approved destination",
                               f"{received:g} USDT from the official contract reached {short(expected_dest)}."))
            if expected_amount:
                exp = Decimal(str(expected_amount))
                got = Decimal(str(received))
                if got < exp:
                    status = "PARTIAL"
                    findings.append(_f("high", "Underpaid",
                                       f"Invoice is {expected_amount:g} USDT; received {received:g}. Outstanding: {float(exp - got):g}."))
                elif got > exp:
                    findings.append(_f("medium", "Overpaid", f"Received {received:g} USDT, {float(got - exp):g} more than invoiced."))
            if received < config.CLEVA_MIN_DEPOSIT:
                findings.append(_f("info", "Below Cleva's minimum deposit",
                                   f"Cleva lists a ${config.CLEVA_MIN_DEPOSIT} minimum per stablecoin deposit."))
            need = config.MIN_CONFIRMATIONS.get(network, 12)
            if status == "VERIFIED" and confirmations < need:
                status = "PENDING"
                findings.append(_f("medium", "Waiting for confirmations", f"{confirmations} of {need} confirmations so far."))
    return status, findings, received


# ---------- fetching chain data ----------
def _tron_headers():
    h = {"accept": "application/json"}
    if config.TRONGRID_API_KEY:
        h["TRON-PRO-API-KEY"] = config.TRONGRID_API_KEY
    return h


def _verify_tron(txid, expected_dest, expected_amount):
    if not re.fullmatch(r"[0-9a-fA-F]{64}", txid):
        raise ValueError("A TRON transaction hash is 64 hex characters.")
    base = config.TRON_API_URL
    with httpx.Client(timeout=20, headers=_tron_headers()) as c:
        r = c.get(f"{base}/v1/transactions/{txid}/events")
        r.raise_for_status()
        events = r.json().get("data", []) or []
        if not events:
            tx = c.post(f"{base}/wallet/gettransactionbyid", json={"value": txid}).json()
            status = "NO_TRANSFER" if tx else "NOT_FOUND"
            msg = ("Transaction exists but contains no token transfer." if tx
                   else "Transaction not found on TRON. Check the hash and network.")
            return _result("TRON", txid, status, 0, [], [_f("high", status.replace("_", " ").title(), msg)], 0.0)
        head = c.post(f"{base}/wallet/getnowblock", json={}).json()["block_header"]["raw_data"]["number"]
    transfers, block = [], 0
    for e in events:
        if e.get("event_name") != "Transfer":
            continue
        res = e.get("result", {})
        block = max(block, int(e.get("block_number", 0)))
        transfers.append({
            "contract": _to_tron(e.get("contract_address", "")),
            "official": _to_tron(e.get("contract_address", "")) == config.TRON_USDT,
            "from": _to_tron(res.get("from", res.get("0", ""))),
            "to": _to_tron(res.get("to", res.get("1", ""))),
            "amount": int(res.get("value", res.get("2", 0))) / 1_000_000,
        })
    conf = max(0, head - block + 1) if block else 0
    status, findings, received = evaluate_settlement("TRON", transfers, conf, expected_dest, expected_amount)
    return _result("TRON", txid, status, conf, transfers, findings, received)


def _rpc(c, method, params):
    r = c.post(config.ETH_RPC_URL, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    r.raise_for_status()
    j = r.json()
    if "error" in j:
        raise RuntimeError(str(j["error"]))
    return j.get("result")


def _verify_eth(txid, expected_dest, expected_amount):
    if not txid.startswith("0x"):
        txid = "0x" + txid
    if not re.fullmatch(r"0x[0-9a-fA-F]{64}", txid):
        raise ValueError("An Ethereum transaction hash is 0x followed by 64 hex characters.")
    with httpx.Client(timeout=20) as c:
        receipt = _rpc(c, "eth_getTransactionReceipt", [txid])
        if not receipt:
            pending = _rpc(c, "eth_getTransactionByHash", [txid])
            status = "PENDING" if pending else "NOT_FOUND"
            msg = "Transaction is not mined yet." if pending else "Transaction not found on Ethereum. Check the hash and network."
            return _result("ETHEREUM", txid, status, 0, [], [_f("high", status.title(), msg)], 0.0)
        head = int(_rpc(c, "eth_blockNumber", []), 16)
    if receipt.get("status") != "0x1":
        return _result("ETHEREUM", txid, "FAILED", 0, [], [_f("critical", "Transaction failed", "The transaction was reverted on-chain.")], 0.0)
    conf = head - int(receipt["blockNumber"], 16) + 1
    transfers = []
    for log in receipt.get("logs", []):
        topics = log.get("topics", [])
        if len(topics) == 3 and topics[0].lower() == TRANSFER_TOPIC:
            data = log.get("data", "0x")
            transfers.append({
                "contract": log["address"],
                "official": log["address"].lower() == config.ETH_USDT.lower(),
                "from": "0x" + topics[1][-40:],
                "to": "0x" + topics[2][-40:],
                "amount": (int(data, 16) if data not in ("0x", "") else 0) / 1_000_000,
            })
    status, findings, received = evaluate_settlement("ETHEREUM", transfers, conf, expected_dest, expected_amount)
    return _result("ETHEREUM", txid, status, conf, transfers, findings, received)


def _result(network, txid, status, conf, transfers, findings, received, simulated=False):
    return {
        "network": network, "txid": txid, "status": status, "simulated": simulated,
        "confirmations": conf, "required_confirmations": config.MIN_CONFIRMATIONS.get(network, 12),
        "transfers": transfers, "findings": findings, "received": received,
    }


def _simulate(network, key, expected_dest, expected_amount):
    amt = float(expected_amount or 0)
    to, official, value, conf = expected_dest, True, amt, config.MIN_CONFIRMATIONS.get(network, 12)
    if key == "DEMO-FAKE":
        official = False
    elif key == "DEMO-WRONG":
        to = tron_address_from_label("intentlock-demo-attacker") if network == "TRON" else "0x" + "ab" * 20
    elif key == "DEMO-PARTIAL":
        value = round(amt * 0.8, 6)
    elif key == "DEMO-PENDING":
        conf = 3
    elif key != "DEMO-REAL":
        raise ValueError("Unknown demo hash. Use DEMO-REAL, DEMO-FAKE, DEMO-WRONG, DEMO-PARTIAL or DEMO-PENDING.")
    fake = tron_address_from_label("fake-usdt") if network == "TRON" else "0x" + "cd" * 20
    sender = tron_address_from_label("payer") if network == "TRON" else "0x" + "11" * 20
    transfers = [{"contract": official_token(network) if official else fake, "official": official,
                  "from": sender, "to": to, "amount": value}]
    status, findings, received = evaluate_settlement(network, transfers, conf, expected_dest, expected_amount)
    return _result(network, key, status, conf, transfers, findings, received, simulated=True)


def verify_settlement(network, txid, expected_dest, expected_amount):
    net = norm_network(network)
    txid = (txid or "").strip()
    if txid.upper().startswith("DEMO"):
        return _simulate(net, txid.upper(), expected_dest, expected_amount)
    if net == "TRON":
        return _verify_tron(txid, expected_dest, expected_amount)
    if net == "ETHEREUM":
        return _verify_eth(txid, expected_dest, expected_amount)
    raise ValueError("On-chain verification supports TRON and Ethereum wallet payments only.")
