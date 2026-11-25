"""Offline self-test: no internet, no server needed.   Run:  python selftest.py"""
import time

from backend import chain, extract, rules, signing

fails = 0


def check(name, cond):
    global fails
    print(("PASS  " if cond else "FAIL  ") + name)
    if not cond:
        fails += 1


approved = chain.tron_address_from_label("intentlock-demo-approved")
attacker = chain.tron_address_from_label("intentlock-demo-attacker")

# addresses
check("generated TRON address is valid", chain.tron_is_valid(approved))
bad_addr = approved[:-1] + ("A" if approved[-1] != "A" else "B")
check("a one-character typo is detected", not chain.tron_is_valid(bad_addr))
check("official Ethereum USDT address is valid", chain.is_valid_address("ETHEREUM", "0xdAC17F958D2ee523a2206206994597C13D831ec7"))
check("lookalike domain distance is 1", rules.levenshtein("globaltrade.example", "g1obaltrade.example") == 1)

# signing
addr, key = signing.new_keypair()
msg = signing.build_message("Global Trade Ltd", "INV-2026-001", 8000, chain.official_token("TRON"), "TRON", approved, time.time() + 3600)
signature = signing.sign_message(msg, key)
ok, reason, m = signing.verify_instruction({"message": msg, "signature": signature}, addr)
check("genuine signature verifies", ok)
tampered = dict(msg, destination=attacker)
ok2, _, _ = signing.verify_instruction({"message": tampered, "signature": signature}, addr)
check("changing the destination breaks the signature", not ok2)

# extraction
text_a = (f"From: Global Trade Ltd <billing@globaltrade.example>\nInvoice No: INV-2026-001\nTotal: 8,000 USDT\n"
          f"Network: TRON (TRC20)\nUSDT wallet: {approved}\n")
text_b = (f"From: Global Trade Ltd <billing@g1obaltrade.example>\nInvoice No: INV-2026-001\nTotal: 8,000 USDT\n"
          f"URGENT: we have changed our wallet, do not call.\nNetwork: TRON (TRC20)\nUSDT wallet: {attacker}\n")
ex_a, ex_b = extract.heuristic_extract(text_a), extract.heuristic_extract(text_b)
check("reads amount", ex_a["amount"] == 8000.0)
check("reads wallet", ex_a["destination"] == approved)
check("reads invoice number", ex_a["invoice_number"] == "INV-2026-001")
check("reads supplier name", ex_a["supplier_name"] == "Global Trade Ltd")

# rules
supplier = {"name": "Global Trade Ltd", "known_domain": "globaltrade.example", "signing_address": addr}
dests = [{"kind": "wallet", "network": "TRON", "address": approved}]
sig = {"present": True, "valid": ok, "reason": reason, "message": m, "expired": False, "replay": False}

status_a, _ = rules.decide(rules.evaluate(ex_a, supplier, dests, [], "globaltrade.example", text_a, sig))
check("genuine invoice is approved", status_a == "approved")
status_b, _ = rules.decide(rules.evaluate(ex_b, supplier, dests, [], "g1obaltrade.example", text_b, sig))
check("swapped wallet with the genuine signature attached is withheld", status_b == "withheld")
status_b2, _ = rules.decide(rules.evaluate(ex_b, supplier, dests, [], "g1obaltrade.example", text_b, None))
check("swapped wallet with no signature is withheld", status_b2 == "withheld")
status_new, _ = rules.decide(rules.evaluate(ex_a, None, [], [], "", text_a, None))
check("unknown supplier needs verification", status_new == "needs_verification")

# address and network checks
from backend import addresses

sol = "So11111111111111111111111111111111111111112"
btc = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
usdt_eth = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
check("detects a Solana address", addresses.detect(sol)["family"] == "SOLANA")
check("detects a valid Bitcoin address", addresses.detect(btc)["family"] == "BITCOIN" and addresses.detect(btc)["valid"])
check("detects a TRON address", addresses.detect(approved)["family"] == "TRON")
check("Solana address on TRON is critical", any(f["severity"] == "critical" for f in addresses.preflight(sol, "TRON", "USDT")))
check("Bitcoin address on Ethereum is critical", any(f["severity"] == "critical" for f in addresses.preflight(btc, "ETHEREUM", "USDT")))
check("BTC asset to a 0x address is critical", any(f["id"] == "ADDRESS_ASSET_MISMATCH" for f in addresses.preflight(usdt_eth, "ETHEREUM", "BTC")))
check("USDT on BNB Chain is flagged unsupported", any(f["id"] == "UNSUPPORTED_NETWORK" for f in addresses.preflight(usdt_eth, "BSC", "USDT")))
check("correct TRON USDT address passes", all(f["severity"] == "info" for f in addresses.preflight(approved, "TRON", "USDT")))
check("extraction finds a Solana address", extract.heuristic_extract(f"Pay 50 USDT on Solana to {sol}")["destination"] == sol)

# address poisoning
eth_a = "0x" + "a1b2" + "11" * 16 + "c3d4"
eth_b = "0x" + "a1b2" + "22" * 16 + "c3d4"
check("lookalike address is detected", addresses.lookalikes(eth_b, [eth_a]) == [eth_a])
check("the same address is not a lookalike", addresses.lookalikes(eth_a, [eth_a]) == [])
check("unrelated addresses are not lookalikes", addresses.lookalikes(attacker, [approved]) == [])
check("poisoning is a critical finding", any(f["severity"] == "critical" for f in addresses.poison_findings(eth_b, [eth_a])))

# settlement logic
real = [{"contract": chain.official_token("TRON"), "official": True, "from": attacker, "to": approved, "amount": 8000}]
fake = [dict(real[0], official=False)]
wrong = [dict(real[0], to=attacker)]
check("real payment verifies", chain.evaluate_settlement("TRON", real, 25, approved, 8000)[0] == "VERIFIED")
check("too few confirmations is pending", chain.evaluate_settlement("TRON", real, 3, approved, 8000)[0] == "PENDING")
check("fake token is caught", chain.evaluate_settlement("TRON", fake, 25, approved, 8000)[0] == "FAKE_TOKEN")
check("wrong destination is caught", chain.evaluate_settlement("TRON", wrong, 25, approved, 8000)[0] == "MISMATCH")
check("underpayment is caught", chain.evaluate_settlement("TRON", real, 25, approved, 9000)[0] == "PARTIAL")
check("simulated hash works", chain.verify_settlement("TRON", "DEMO-FAKE", approved, 8000)["status"] == "FAKE_TOKEN")

print("\nAll good." if not fails else f"\n{fails} check(s) failed. Copy this output and send it to Claude.")
