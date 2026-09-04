import os
from pathlib import Path
from typing import List, Optional

from dotenv import load_dotenv


def _clean_csv(value: str) -> List[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _clean_optional(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


APP_ENV = os.getenv("APP_ENV", "development").strip().lower()

SECRET_KEY = os.getenv("SECRET_KEY", "").strip()
ALGORITHM = os.getenv("ALGORITHM", "HS256").strip()
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "480"))
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "").strip()
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH", "").strip()

FRONTEND_ORIGINS = _clean_csv(
    os.getenv(
        "FRONTEND_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:8000",
    )
)
FRONTEND_ORIGIN_REGEX = _clean_optional(os.getenv("FRONTEND_ORIGIN_REGEX"))

ALLOW_PRIVATE_SCAN_TARGETS = os.getenv("ALLOW_PRIVATE_SCAN_TARGETS", "false").strip().lower() == "true"

DISCOVERY_MAX_ASSETS = os.getenv("DISCOVERY_MAX_ASSETS", "").strip()
DISCOVERY_MAX_ASSETS = int(DISCOVERY_MAX_ASSETS) if DISCOVERY_MAX_ASSETS else None

DOCS_ENABLED = os.getenv("ENABLE_API_DOCS", "false" if APP_ENV == "production" else "true").strip().lower() == "true"

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./qguardian.db").strip()

# Load local development secrets only outside production so Render relies on its own env vars.
if APP_ENV != "production":
    _ENV_PATH = Path(__file__).resolve().parents[1] / ".env"
    load_dotenv(_ENV_PATH)
