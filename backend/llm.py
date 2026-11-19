"""Optional LLM helper. The LLM only READS documents and EXPLAINS results. It never decides."""
import json
import re

import httpx

from backend import config


def enabled() -> bool:
    return config.llm_enabled()


def _chat(messages):
    r = httpx.post(
        f"{config.LLM_BASE_URL}/chat/completions",
        headers={"Authorization": f"Bearer {config.LLM_API_KEY}", "Content-Type": "application/json"},
        json={"model": config.LLM_MODEL, "messages": messages},
        timeout=60,
    )
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]


def _parse_json(txt):
    txt = re.sub(r"^```(?:json)?|```$", "", txt.strip(), flags=re.M).strip()
    start, end = txt.find("{"), txt.rfind("}")
    return json.loads(txt[start:end + 1])


EXTRACT_SYSTEM = (
    "You extract payment details from invoices and payment messages. Return ONLY a JSON object with keys: "
    "supplier_name, invoice_number, amount (number), currency, network (TRON, ETHEREUM, BANK or null), "
    "destination (wallet address or bank account/IBAN copied exactly as written), sender_email. "
    "Use null for anything absent. Never guess or invent values."
)


def extract_json(text, image_data_url=None):
    if image_data_url:
        content = [{"type": "text", "text": "Extract the payment details from this invoice image."},
                   {"type": "image_url", "image_url": {"url": image_data_url}}]
    else:
        content = "Document:\n" + text
    out = _chat([{"role": "system", "content": EXTRACT_SYSTEM}, {"role": "user", "content": content}])
    return _parse_json(out)


def explain(status, findings):
    issues = [f"- {f['title']}: {f['detail']}" for f in findings if f["severity"] != "info"] or ["- No warning signs."]
    system = ("You explain payment-risk findings to a small business owner in plain, simple English. "
              "Use ONLY the findings provided. Do not add facts. Never say a payment is safe or guaranteed. "
              "Maximum 80 words. If there are warnings, tell them to verify with the supplier on a trusted channel.")
    return _chat([{"role": "system", "content": system},
                  {"role": "user", "content": f"Decision: {status}\nFindings:\n" + "\n".join(issues)}]).strip()
