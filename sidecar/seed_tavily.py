"""Seed the Tavily API key into studio.db settings."""
import sqlite3
from pathlib import Path

db_path = Path.home() / ".agentarmor" / "studio.db"
conn = sqlite3.connect(str(db_path))
conn.execute(
    "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
    ("tavily_api_key", "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"),
)
conn.commit()
conn.close()
print("Tavily API key saved to studio.db settings")
