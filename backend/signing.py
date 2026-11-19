"""Supplier-signed payment instructions (EIP-712 typed data).

A supplier signs {supplier, invoice, amount, token, network, destination, expiry, nonce}.
Changing any field invalidates the signature. Replay protection (nonce + expiry) is
enforced by IntentLock itself, because EIP-712 does not provide it.

DEMO NOTE: in this prototype the server holds demo private keys so you can show the flow.
In a real deployment the supplier signs on their own device and the server never sees the key.
"""
import secrets
from decimal import Decimal

from eth_account import Account
from eth_account.messages import encode_typed_data

DOMAIN = {"name": "IntentLock", "version": "1", "chainId": 1}
TYPES = {
    "PaymentInstruction": [
        {"name": "supplier", "type": "string"},
        {"name": "invoiceId", "type": "string"},
        {"name": "amount", "type": "string"},
        {"name": "token", "type": "string"},
        {"name": "network", "type": "string"},
        {"name": "destination", "type": "string"},
        {"name": "expiry", "type": "uint256"},
        {"name": "nonce", "type": "string"},
    ]
}


def norm_amount(a) -> str:
    return format(Decimal(str(a)).normalize(), "f")


def _hex(b) -> str:
    h = b.hex()
    return h if h.startswith("0x") else "0x" + h


def new_keypair():
    acct = Account.create()
    return acct.address, _hex(acct.key)


def build_message(supplier, invoice_id, amount, token, network, destination, expiry, nonce=None):
    return {
        "supplier": supplier,
        "invoiceId": invoice_id or "",
        "amount": norm_amount(amount),
        "token": token,
        "network": network,
        "destination": destination,
        "expiry": int(expiry),
        "nonce": nonce or secrets.token_hex(8),
    }


def _signable(message):
    return encode_typed_data(domain_data=DOMAIN, message_types=TYPES, message_data=message)


def sign_message(message, private_key) -> str:
    key = private_key if private_key.startswith("0x") else "0x" + private_key
    signed = Account.sign_message(_signable(message), private_key=key)
    return _hex(signed.signature)


def recover_signer(message, signature) -> str:
    sig = signature[2:] if signature.startswith("0x") else signature
    return Account.recover_message(_signable(message), signature=bytes.fromhex(sig))


def verify_instruction(signed, expected_signer):
    """Returns (ok, reason, message)."""
    try:
        message = signed["message"]
        recovered = recover_signer(message, signed["signature"])
    except Exception as e:  # malformed JSON shape, wrong types, bad signature bytes
        return False, f"Signature could not be verified ({e.__class__.__name__}).", None
    if recovered.lower() != expected_signer.lower():
        return False, ("Signature does not match the supplier's registered signing key. "
                       "The instruction was altered after signing, or signed by someone else."), message
    return True, "Signature is valid for the supplier's registered signing key.", message
