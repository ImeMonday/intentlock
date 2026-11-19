"""Settings, read from environment variables or a .env file in the project root."""
import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

DB_PATH = os.getenv("DB_PATH", str(BASE_DIR / "intentlock.db"))

# Optional LLM (any OpenAI-compatible chat-completions API). Blank = run without AI.
LLM_API_KEY = os.getenv("LLM_API_KEY", "").strip()
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1").strip().rstrip("/")
LLM_MODEL = os.getenv("LLM_MODEL", "").strip()
LLM_VISION = os.getenv("LLM_VISION", "0").strip() == "1"

# Public chain data
TRON_API_URL = os.getenv("TRON_API_URL", "https://api.trongrid.io").strip().rstrip("/")
TRONGRID_API_KEY = os.getenv("TRONGRID_API_KEY", "").strip()
ETH_RPC_URL = os.getenv("ETH_RPC_URL", "https://ethereum-rpc.publicnode.com").strip()

# Official Tether (USDT) contracts
TRON_USDT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
ETH_USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"

MIN_CONFIRMATIONS = {"TRON": 20, "ETHEREUM": 12}
CLEVA_MIN_DEPOSIT = 10


def llm_enabled() -> bool:
    return bool(LLM_API_KEY and LLM_MODEL)
