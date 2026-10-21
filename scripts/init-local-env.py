#!/usr/bin/env python3
"""Create development-only settings without copying deployment secrets."""
from pathlib import Path
import os
import secrets

root = Path(__file__).resolve().parents[1]
destination = root / ".env"
settings = (root / ".env.example").read_text(encoding="utf-8")
password = secrets.token_hex(24)
values = {
    "SECRET_KEY": secrets.token_hex(32),
    "BEACON_CSRF_SECRET": secrets.token_hex(32),
    "ZAP_API_KEY": secrets.token_hex(32),
    "POSTGRES_PASSWORD": password,
    "DATABASE_URL": f"postgresql+psycopg://beacon:{password}@postgres:5432/beacon",
    "VITE_TURNSTILE_SITE_KEY": "",
}
lines = []
for line in settings.splitlines():
    key = line.split("=", 1)[0]
    lines.append(f"{key}={values[key]}" if key in values else line)
try:
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
except FileExistsError:
    raise SystemExit("Refusing to overwrite an existing .env file.")
with os.fdopen(fd, "w", encoding="utf-8") as handle:
    handle.write("\n".join(lines) + "\n")
print("Created local .env with fresh development secrets; configure SMTP before registration.")
