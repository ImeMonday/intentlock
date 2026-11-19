"""Deterministic risk rules. AI can read documents and explain results, but THESE rules decide."""
from decimal import Decimal

from backend import chain

RANK = {"info": 0, "medium": 1, "high": 2, "critical": 3}

URGENCY = ["urgent", "urgently", "immediately", "asap", "right away", "do not call", "don't call",
           "dont call", "confidential", "keep this between", "in a meeting", "unavailable by phone"]
CHANGE = ["new account", "new bank", "new wallet", "changed our", "we have changed", "updated bank",
          "updated payment", "updated wallet", "change of bank", "change of wallet",
          "do not use the old", "do not use the previous", "no longer use", "no longer valid"]


def F(fid, severity, title, detail, blocking=False):
    return {"id": fid, "severity": severity, "title": title, "detail": detail, "blocking": blocking}


def levenshtein(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _bank_norm(s):
    return "".join(ch for ch in (s or "") if ch.isalnum()).lower()


def same_destination(kind, network, a, b):
    if kind == "bank":
        return _bank_norm(a) == _bank_norm(b)
    return chain.same_address(network, a, b)


def _dec(x):
    try:
        return Decimal(str(x))
    except Exception:
        return None


def evaluate(ex, supplier, destinations, history, sender_domain, text, sig):
    """ex: extracted fields. supplier: dict or None. destinations: approved list.
    history: earlier checks for this supplier. sig: signed-instruction result or None."""
    findings = []
    dest, kind, net, amount = ex.get("destination"), ex.get("dest_kind"), ex.get("network"), ex.get("amount")
    low = (text or "").lower()

    # 1. Destination present and well-formed
    if not dest:
        findings.append(F("NO_DESTINATION", "high", "No payment destination found",
                          "The invoice does not contain a wallet address or bank account we could read.", True))
    elif kind == "wallet":
        guess = chain.guess_network(dest)
        if guess is None or not chain.is_valid_address(guess, dest):
            findings.append(F("INVALID_ADDRESS", "critical", "Address is not valid",
                              "This does not look like a valid TRON or Ethereum address (a typo or tampering). "
                              "Sending to it could lose the funds.", True))
        elif net and net != guess:
            findings.append(F("NETWORK_MISMATCH", "high", "Network does not match the address",
                              f"The invoice says {net} but the address is a {guess} address. "
                              "Paying on the wrong network can lose funds permanently."))

    if ex.get("currency") and ex["currency"] not in ("USDT", "USD"):
        findings.append(F("CURRENCY", "medium", "Unexpected currency", f"Invoice currency is {ex['currency']}."))

    # 2. Supplier history
    if supplier is None:
        findings.append(F("NEW_PAYEE", "high", "New or unrecognised payee",
                          "There is no verified payment history for this supplier. Verify the payment details "
                          "with them on a contact you already trust before paying."))
    else:
        if not destinations:
            findings.append(F("NO_APPROVED_DESTINATION", "high", "Supplier has no approved destination yet",
                              "Confirm the payment details out-of-band before the first payment."))
        elif dest and not any(same_destination(kind, net, d["address"], dest) and d["kind"] == kind
                              for d in destinations):
            approved = ", ".join(chain.short(d["address"]) for d in destinations)
            findings.append(F("DESTINATION_CHANGED", "critical", "Destination differs from the approved record",
                              f"{chain.short(dest)} is not one of {supplier['name']}'s approved destinations ({approved})."))

        kd = (supplier.get("known_domain") or "").lower()
        sd = (sender_domain or "").lower()
        if kd:
            if not sd:
                findings.append(F("SENDER_NOT_PROVIDED", "info", "Sender not checked", "No sender email or domain was provided."))
            elif sd != kd and not sd.endswith("." + kd):
                if levenshtein(sd, kd) <= 2:
                    findings.append(F("LOOKALIKE_DOMAIN", "high", "Sender domain looks like the supplier's",
                                      f"{sd} is almost identical to the known domain {kd}. This is a common impersonation trick."))
                else:
                    findings.append(F("SENDER_DOMAIN_DIFFERS", "medium", "Sender domain differs from the supplier's",
                                      f"{sd} is not the known domain {kd}."))

        prev = [h["amount"] for h in history if h.get("amount")]
        if amount and prev and amount > 3 * max(prev):
            findings.append(F("AMOUNT_ANOMALY", "medium", "Unusually large amount",
                              f"{amount:g} is more than 3x the largest earlier payment ({max(prev):g})."))

        inv = (ex.get("invoice_number") or "").strip().lower()
        if inv:
            same = [h for h in history if (h.get("invoice_number") or "").strip().lower() == inv]
            if same:
                changed = any((h.get("destination") or "") != (dest or "") or h.get("amount") != amount for h in same)
                if changed:
                    findings.append(F("DUPLICATE_INVOICE_CHANGED", "high", "Invoice number reused with different details",
                                      f"Invoice {ex.get('invoice_number')} was seen before with a different amount or destination."))
                elif any(h.get("paid") for h in same):
                    findings.append(F("DUPLICATE_PAID", "medium", "This invoice was already paid",
                                      "A verified payment for this invoice already exists."))
                else:
                    findings.append(F("RECHECKED", "info", "Invoice seen before", "Same details as an earlier check."))

    # 3. Message language
    change_hits = [p for p in CHANGE if p in low]
    urgency_hits = [p for p in URGENCY if p in low]
    if change_hits:
        findings.append(F("CHANGE_ANNOUNCED", "high", "Message announces a change of payment details",
                          "Phrases found: " + ", ".join(change_hits[:3]) + "."))
    if urgency_hits:
        findings.append(F("URGENCY_PRESSURE", "medium", "Pressure or secrecy language",
                          "Phrases found: " + ", ".join(urgency_hits[:3]) + "."))

    # 4. Supplier signature
    if supplier and supplier.get("signing_address"):
        if not sig or not sig.get("present"):
            findings.append(F("UNSIGNED_INSTRUCTION", "high", "No supplier signature",
                              "This supplier signs their payment instructions, but this invoice has none."))
        elif not sig["valid"]:
            findings.append(F("SIG_INVALID", "critical", "Supplier signature is not valid", sig["reason"]))
        else:
            m = sig["message"]
            bad = []
            m_net = chain.norm_network(m.get("network"))
            if not dest or not same_destination(kind, m_net, m.get("destination"), dest):
                bad.append("destination")
            a, b = _dec(m.get("amount")), _dec(amount)
            if a is None or b is None or a != b:
                bad.append("amount")
            if ex.get("invoice_number") and (m.get("invoiceId") or "").lower() != ex["invoice_number"].lower():
                bad.append("invoice number")
            if kind == "wallet" and m.get("token") != chain.official_token(m_net):
                bad.append("token")
            if bad:
                findings.append(F("SIG_MISMATCH", "critical", "Signed instruction does not match this invoice",
                                  "Differences in: " + ", ".join(bad) + ". The supplier signed something different."))
            else:
                findings.append(F("SIG_OK", "info", "Supplier signature matches the invoice", sig["reason"]))
            if sig.get("expired"):
                findings.append(F("SIG_EXPIRED", "high", "Signed instruction has expired", "Ask the supplier to sign a new one."))
            if sig.get("replay"):
                findings.append(F("SIG_REPLAY", "critical", "Signed instruction already used",
                                  "This signature was already used for a verified payment."))
    elif sig and sig.get("present"):
        findings.append(F("SIG_IGNORED", "info", "Signature ignored", "This supplier has no registered signing key."))

    if amount and amount < 10 and ex.get("currency") == "USDT":
        findings.append(F("CLEVA_MIN", "info", "Below Cleva's minimum deposit", "Cleva lists a $10 minimum per stablecoin deposit."))
    return findings


def decide(findings):
    top = max((RANK[f["severity"]] for f in findings), default=0)
    if top >= 3:
        return "withheld", "CRITICAL"
    if top == 2:
        return "needs_verification", "HIGH"
    if top == 1:
        return "needs_verification", "MEDIUM"
    return "approved", "LOW"


def template_explanation(status, findings):
    issues = [f["title"] for f in findings if RANK[f["severity"]] >= 1]
    if not issues:
        return "Payment details match this supplier's verified record. No warning signs were found."
    lead = "Approval withheld." if status == "withheld" else "Verify before paying."
    return (f"{lead} {'; '.join(issues[:4])}. Confirm the details with the supplier using a phone number "
            "or channel you already trust. Do not reply to the message that contained the new details.")
