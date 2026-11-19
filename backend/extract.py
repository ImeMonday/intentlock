"""Reads invoices and messages into structured fields.

Works with no AI (regex rules). If an LLM is configured, it reads the document too, but anything
it returns for the address or invoice number must appear verbatim in the source text, otherwise it is ignored.
"""
import base64
import io
import re

from backend import chain, config, llm

TRON_RE = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")
ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
KEYS = ("supplier_name", "invoice_number", "amount", "currency", "network", "destination", "dest_kind", "sender_email")


def pdf_to_text(data: bytes) -> str:
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(data))
    return "\n".join((p.extract_text() or "") for p in reader.pages).strip()


def normalize(f):
    try:
        f["amount"] = float(str(f["amount"]).replace(",", "")) if f.get("amount") not in (None, "") else None
    except ValueError:
        f["amount"] = None
    if f.get("currency"):
        f["currency"] = str(f["currency"]).upper()
    f["network"] = chain.norm_network(f.get("network"))
    d = (str(f.get("destination") or "")).strip() or None
    f["destination"] = d
    if d:
        g = chain.guess_network(d)
        if g:
            f["dest_kind"] = "wallet"
            f["network"] = f["network"] or g
        else:
            f["dest_kind"] = "bank"
            f["network"] = "BANK"
    else:
        f["dest_kind"] = None
    return f


def heuristic_extract(text):
    t = text or ""
    f = {k: None for k in KEYS}

    m = re.search(r"(?:^|\n)[ \t]*(?:from|supplier|vendor|billed by|issued by)[ \t]*[:\-][ \t]*([^\n]+)", t, re.I)
    if m:
        f["supplier_name"] = (re.sub(r"<[^>]*>", "", m.group(1)).strip(" -,")[:80]) or None

    for m in re.finditer(r"invoice[ \t]*(?:no\.?|number|#|id)?[ \t]*[:#\-]?[ \t]*([A-Za-z0-9][A-Za-z0-9\-_/]{2,})", t, re.I):
        if any(ch.isdigit() for ch in m.group(1)):
            f["invoice_number"] = m.group(1)
            break

    for pat in (r"(?:total|amount due|balance due)[^0-9\n]{0,25}([0-9][0-9,]*(?:\.[0-9]+)?)",
                r"(?:amount|payment of|pay)[^0-9\n]{0,25}([0-9][0-9,]*(?:\.[0-9]+)?)",
                r"\$[ \t]*([0-9][0-9,]*(?:\.[0-9]+)?)",
                r"([0-9][0-9,]*(?:\.[0-9]+)?)[ \t]*(?:USDT|USD)\b"):
        m = re.search(pat, t, re.I)
        if m:
            try:
                f["amount"] = float(m.group(1).replace(",", ""))
                break
            except ValueError:
                pass

    if re.search(r"\bUSDT\b", t, re.I):
        f["currency"] = "USDT"
    elif "$" in t or re.search(r"\bUSD\b", t, re.I):
        f["currency"] = "USD"

    if re.search(r"TRC[ \-]?20|\bTRON\b", t, re.I):
        f["network"] = "TRON"
    elif re.search(r"ERC[ \-]?20|\bEthereum\b", t, re.I):
        f["network"] = "ETHEREUM"

    cands = ([(m.start(), "TRON", m.group(0)) for m in TRON_RE.finditer(t)]
             + [(m.start(), "ETHEREUM", m.group(0)) for m in ETH_RE.finditer(t)])
    if cands:
        cands.sort()
        pick = next((c for c in cands if c[1] == f["network"]), cands[0])
        f["destination"] = pick[2]
        f["network"] = f["network"] or pick[1]
    else:
        m = (re.search(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", t)
             or re.search(r"(?:account|acct)[^0-9\n]{0,20}([0-9][0-9 \-]{6,20}[0-9])", t, re.I))
        if m:
            f["destination"] = (m.group(1) if m.re.groups else m.group(0)).strip()

    m = re.search(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", t)
    if m:
        f["sender_email"] = m.group(0)
    return normalize(f)


def _merge(base, data, text):
    out = dict(base)
    for k in KEYS:
        v = data.get(k)
        if v in (None, "", "null"):
            continue
        if k in ("destination", "invoice_number") and text and str(v) not in text:
            continue  # AI output must appear verbatim in the source, otherwise ignore it
        out[k] = v
    return normalize(out)


def extract_fields(text, image=None):
    """image: (bytes, mime) or None. Returns (fields, method)."""
    if image and not (llm.enabled() and config.LLM_VISION):
        raise ValueError("Image invoices need an LLM with vision (set LLM_VISION=1). Paste the invoice text instead.")
    base = heuristic_extract(text) if text else {k: None for k in KEYS}
    if llm.enabled() and (text or image):
        try:
            url = None
            if image:
                url = f"data:{image[1]};base64,{base64.b64encode(image[0]).decode()}"
            data = llm.extract_json(text, url)
            return _merge(base, data, text), "AI reading, checked against the source text"
        except Exception as e:
            return base, f"Built-in rules (AI unavailable: {e.__class__.__name__})"
    return base, "Built-in rules"
