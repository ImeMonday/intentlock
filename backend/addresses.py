"""Wrong-address and wrong-network pre-flight checks.

Deterministic: no AI and no network calls. It answers three questions before you send:
1. What kind of address is this (TRON, Ethereum-style 0x, Solana, Bitcoin) and is it well formed?
2. Does that match the network and asset the payment says it uses?
3. Is that network one Cleva accepts for USDT?
"""
import re

from backend import chain, config

EVM = ("ETHEREUM", "BSC", "POLYGON", "ARBITRUM", "OPTIMISM", "BASE", "AVALANCHE")
FAMILY_OF = {"TRON": "TRON", "SOLANA": "SOLANA", "BITCOIN": "BITCOIN", **{n: "EVM" for n in EVM}}
DEFAULT_NET = {"TRON": "TRON", "EVM": "ETHEREUM", "SOLANA": "SOLANA", "BITCOIN": "BITCOIN"}
FAMILY_NAME = {"TRON": "TRON", "EVM": "Ethereum-style (0x)", "SOLANA": "Solana", "BITCOIN": "Bitcoin"}
NET_NAME = {"TRON": "TRON (TRC20)", "ETHEREUM": "Ethereum (ERC20)", "BSC": "BNB Smart Chain (BEP20)", "POLYGON": "Polygon",
            "ARBITRUM": "Arbitrum", "OPTIMISM": "Optimism", "BASE": "Base", "AVALANCHE": "Avalanche",
            "SOLANA": "Solana", "BITCOIN": "Bitcoin"}
NATIVE_FAMILY = {"BTC": "BITCOIN", "ETH": "EVM", "SOL": "SOLANA", "TRX": "TRON"}
BASE58 = re.compile(r"[1-9A-HJ-NP-Za-km-z]+")
B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def F(fid, sev, title, detail, blocking=False):
    return {"id": fid, "severity": sev, "title": title, "detail": detail, "blocking": blocking}


# ---------- Bitcoin bech32 (bc1...) checksum ----------
def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= gen[i]
    return chk


def _bech32_ok(addr):
    if addr != addr.lower() and addr != addr.upper():
        return False
    a = addr.lower()
    pos = a.rfind("1")
    if pos < 1 or pos + 7 > len(a) or len(a) > 90:
        return False
    hrp, data = a[:pos], a[pos + 1:]
    if hrp != "bc" or any(c not in B32 for c in data):
        return False
    values = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp] + [B32.index(c) for c in data]
    return _polymod(values) in (1, 0x2BC830A3)  # bech32 or bech32m


# ---------- detection ----------
def detect(addr):
    """Returns {family, valid, note}. family is TRON, EVM, SOLANA, BITCOIN or None."""
    a = (addr or "").strip()
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", a):
        ok = chain.is_valid_address("ETHEREUM", a)
        return {"family": "EVM", "valid": ok, "note": "" if ok else "Mixed-case address with a bad checksum. This is usually a typo."}
    if a[:3].lower() == "bc1":
        ok = _bech32_ok(a)
        return {"family": "BITCOIN", "valid": ok, "note": "" if ok else "Bitcoin address checksum fails (typo or tampering)."}
    if a and BASE58.fullmatch(a):
        if a[0] == "T" and len(a) == 34:
            ok = chain.tron_is_valid(a)
            return {"family": "TRON", "valid": ok, "note": "" if ok else "TRON address checksum fails (typo or tampering)."}
        try:
            raw = chain.b58decode(a)
        except ValueError:
            raw = None
        if raw is not None and len(raw) == 25 and raw[0] in (0x00, 0x05) and chain._checksum(raw[:-4]) == raw[-4:]:
            return {"family": "BITCOIN", "valid": True, "note": ""}
        if raw is not None and len(raw) == 32 and 32 <= len(a) <= 44:
            return {"family": "SOLANA", "valid": True, "note": "Solana addresses have no checksum, so a typo cannot be detected."}
        if a[0] in "13" and 26 <= len(a) <= 35:
            return {"family": "BITCOIN", "valid": False, "note": "Bitcoin address checksum fails (typo or tampering)."}
    return {"family": None, "valid": False, "note": "Format not recognised."}


# ---------- token contracts (not wallets) ----------
TOKEN_CONTRACTS = {
    config.TRON_USDT: "USDT on TRON",
    config.ETH_USDT.lower(): "USDT on Ethereum",
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "USDC on Ethereum",
}


def token_findings(addr):
    a = (addr or "").strip()
    name = TOKEN_CONTRACTS.get(a) or TOKEN_CONTRACTS.get(a.lower())
    if not name:
        return []
    return [F("TOKEN_CONTRACT", "critical", "This is a token contract, not a wallet",
              f"{a} is the {name} token contract. Funds sent to a token contract can be lost permanently.", True)]


# ---------- the receiver vault ----------
def _same(a, b):
    a, b = a.strip(), b.strip()
    if a.lower().startswith("0x") and b.lower().startswith("0x"):
        return a.lower() == b.lower()
    return a == b


def _hamming(a, b):
    if a.lower().startswith("0x") and b.lower().startswith("0x"):
        a, b = a.lower(), b.lower()
    return sum(1 for x, y in zip(a, b) if x != y)


def vault_check(addr, saved, supplier_id=None, supplier_name=None):
    """saved: [{address, network, sid, name}]. Returns (findings, match)."""
    a = (addr or "").strip()
    out = []
    match = next((s for s in saved if _same(s["address"], a)), None)
    if match:
        if supplier_id and match["sid"] != supplier_id:
            out.append(F("WRONG_RECEIVER", "critical", f"This address belongs to {match['name']}",
                         f"It is saved for {match['name']}, not the receiver you selected."))
        else:
            out.append(F("VERIFIED_RECEIVER", "info", f"Verified receiver: {match['name']}",
                         f"This address is saved in your vault for {match['name']}."))
        return out, match
    if supplier_id:
        theirs = [s["address"] for s in saved if s["sid"] == supplier_id]
        out.append(F("ADDRESS_CHANGED", "critical", "Not a saved address for this receiver",
                     f"{supplier_name or 'This receiver'} has on file: {', '.join(theirs) or 'nothing'}. This address is different. "
                     "Confirm it with them on a channel you already trust."))
    near = next((s for s in saved if len(s["address"]) == len(a) and _hamming(s["address"], a) <= 2), None)
    if near:
        out.append(F("ADDRESS_TYPO", "critical", f"Looks like a typo of {near['name']}'s address",
                     f"New: {a}  Saved: {near['address']}. Only a character or two differ, which is usually a typing or copy error."))
    elif not supplier_id:
        out.append(F("NOT_IN_VAULT", "medium", "Not in your vault yet",
                     "Confirm this address with the receiver, then save it with their name so future payments can be checked against it."))
    return out, None


# ---------- address poisoning ----------
def lookalikes(addr, known):
    """Known addresses with the same start and end as addr but a different middle."""
    a = (addr or "").strip()
    if not a:
        return []
    evm = a.lower().startswith("0x")
    head = 6 if evm else 4  # "0x" plus 4 hex characters, or the first 4 characters
    norm = (lambda s: s.lower()) if evm else (lambda s: s)
    hits = []
    for k in {x.strip() for x in known if x}:
        if k.lower().startswith("0x") != evm or len(k) != len(a) or norm(k) == norm(a):
            continue
        if norm(k)[:head] == norm(a)[:head] and norm(k)[-4:] == norm(a)[-4:]:
            hits.append(k)
    return hits


def poison_findings(addr, known):
    hits = lookalikes(addr, known)
    if not hits:
        return []
    return [F("ADDRESS_POISONING", "critical", "Looks like an address you have used, but it is different",
              f"New: {addr}  Saved: {hits[0]}. The start and end match but the middle differs. Attackers plant lookalike "
              "addresses in your history hoping you copy the wrong one. Compare every character before sending.")]


# ---------- the pre-flight check ----------
def preflight(addr, stated=None, asset=None):
    """stated: the network the payment says it uses (or None). asset: USDT, USDC, BTC, ETH, SOL..."""
    out = []
    d = detect(addr)
    fam = d["family"]
    net = chain.norm_network(stated) if stated else None
    asset = (asset or "").upper() or None
    if fam is None:
        return [F("UNRECOGNISED_ADDRESS", "critical", "Address format not recognised",
                  "This is not a TRON, Ethereum-style, Solana or Bitcoin address. Do not send to it.", True)]
    tok = token_findings(addr)
    out.extend(tok)
    problems = bool(tok)
    if not d["valid"]:
        out.append(F("INVALID_ADDRESS", "critical", "Address is not valid", d["note"] + " Sending to it could lose the funds.", True))
        problems = True
    net_fam = FAMILY_OF.get(net) if net else None
    if net_fam and net_fam != fam:
        shown = NET_NAME.get(net, net)
        out.append(F("ADDRESS_NETWORK_MISMATCH", "critical", f"{FAMILY_NAME[fam]} address on a {shown} payment",
                     f"This is a {FAMILY_NAME[fam]} address, but the payment is set to {shown}. "
                     "The transfer would fail or the funds could be lost.", True))
        problems = True
    native = NATIVE_FAMILY.get(asset)
    if native and native != fam:
        out.append(F("ADDRESS_ASSET_MISMATCH", "critical", f"{asset} cannot be sent to a {FAMILY_NAME[fam]} address",
                     f"{asset} lives on the {FAMILY_NAME[native]} network, but this is a {FAMILY_NAME[fam]} address.", True))
        problems = True
    if asset == "USDT":
        eff = net or (fam if fam in ("TRON", "SOLANA", "BITCOIN") else None)
        if eff and eff not in config.CLEVA_USDT_NETWORKS:
            out.append(F("UNSUPPORTED_NETWORK", "high", f"USDT on {NET_NAME.get(eff, eff)} is not supported for Cleva deposits",
                         "Cleva accepts USDT on TRON and Ethereum only, so a transfer on another network could be lost. "
                         "Check Cleva's current list before sending."))
            problems = True
    if fam == "EVM" and not net:
        out.append(F("EVM_NETWORK_UNSTATED", "medium", "Network not stated for a 0x address",
                     "The same 0x address exists on Ethereum, BNB Chain, Polygon and others. Confirm the exact network before sending."))
        problems = True
    if fam == "SOLANA" and d["valid"]:
        out.append(F("NO_CHECKSUM", "info", "Solana addresses cannot be checksum-verified", d["note"]))
    if not problems:
        shown = f" on {NET_NAME.get(net, net)}" if net else ""
        out.append(F("ADDRESS_OK", "info", "Address matches the network and asset", f"Valid {FAMILY_NAME[fam]} address{shown}."))
    return out
