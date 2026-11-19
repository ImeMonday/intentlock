# IntentLock (prototype)

Checks a payment instruction (invoice or message) against a supplier's verified history before you pay,
then verifies the USDT payment on-chain and produces a shareable Proof Link.

AI reads and explains. Deterministic rules decide. IntentLock never holds funds or keys.

## Run it in VS Code (Python 3.10 or newer)

Open the `intentlock` folder in VS Code, open a terminal (Ctrl+`), then:

**Windows (PowerShell)**
```
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python selftest.py
uvicorn backend.main:app --reload
```
If activation is blocked: `Set-ExecutionPolicy -Scope Process Bypass`, then activate again.

**Mac or Linux**
```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python selftest.py
uvicorn backend.main:app --reload
```

Open http://127.0.0.1:8000

`python selftest.py` runs offline and should print PASS on every line. If anything prints FAIL or an error, copy the full output and send it back.

No keys are needed. To add AI reading, copy `.env.example` to `.env` and fill in `LLM_API_KEY`, `LLM_BASE_URL` and `LLM_MODEL` (any OpenAI-compatible API).

## Demo script (about 3 minutes)

1. Click **Load demo data**. It creates the supplier "Global Trade Ltd" with an approved wallet and a signing key.
2. Click **Load genuine sample**, then **Sign as supplier (demo)**, then **Run check**. Result: approved.
3. Click **Load tampered sample** (swapped wallet, lookalike domain, urgent message). Keep the signature box as it is. Run check. Result: approval withheld, with every reason listed and the two wallets side by side. Click **Swap to the verified wallet** to switch to the registered one.
4. Click **Tamper with signature**, load the genuine sample again and run: the signature fails.
5. On a genuine check, paste `DEMO-REAL` as the transaction hash and verify. Then try `DEMO-FAKE` (fake USDT) and `DEMO-WRONG`. These are labelled simulated.
6. Open the Proof Link and show the audit trail.

## Live on-chain demo (real, optional)

1. Add a supplier using your own Cleva USDT (TRON) deposit address as the approved wallet.
2. Paste an invoice text for that address and amount (at least 10 USDT, Cleva's minimum deposit).
3. Send that USDT from another wallet or exchange, wait for confirmations, then paste the real transaction hash and verify.

## What is real and what is simulated

- Real: address validation, rule engine, signature checks, audit hash chain, TRON and Ethereum transaction verification via public data.
- Simulated: `DEMO-...` hashes. Demo signing keys are held by the server only to show the flow; real suppliers would sign on their own device.
- Not built: no Cleva API integration (none verified), no payment sending, no blocking of a transfer you make elsewhere. IntentLock gives or withholds approval.

## Files

- `backend/rules.py` risk rules and decision
- `backend/chain.py` address checks and on-chain verification
- `backend/signing.py` supplier-signed instructions (EIP-712)
- `backend/extract.py` reads invoices (rules, PDF, optional AI)
- `backend/main.py` API routes
- `frontend/index.html` main screen, `frontend/proof.html` Proof Link page

## If something fails

- `ModuleNotFoundError`: the virtual environment is not active, or `pip install -r requirements.txt` did not finish.
- Port busy: add `--port 8001` to the uvicorn command.
- TRON verification errors or rate limits: add a free `TRONGRID_API_KEY` to `.env`.
- Delete `intentlock.db` to reset all data.
