"""StudioDB — Persistent SQLite storage for AgentArmor Studio.

Manages three concerns:
1. Agent registry (survives sidecar restart)
2. Event storage (full audit trail)
3. Settings (API keys for Tavily, E2B, etc.)
"""

from __future__ import annotations

import datetime
import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

AGENTARMOR_DIR = Path.home() / ".agentarmor"
STUDIO_DB_PATH = AGENTARMOR_DIR / "studio.db"


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class StudioDB:
    """Thread-safe SQLite wrapper for Studio persistence."""

    def __init__(self, db_path: Path | None = None):
        self._db_path = db_path or STUDIO_DB_PATH
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_schema()

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA foreign_keys=ON")
        return self._local.conn

    def _init_schema(self):
        c = self._conn()
        c.executescript("""
            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                name TEXT DEFAULT '',
                framework TEXT DEFAULT 'custom',
                agent_type TEXT DEFAULT 'general',
                system_prompt TEXT DEFAULT '',
                layers_enabled TEXT DEFAULT '[]',
                tools_enabled TEXT DEFAULT '[]',
                provider TEXT DEFAULT 'ollama',
                provider_model TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                last_heartbeat TEXT NOT NULL,
                status TEXT DEFAULT 'online',
                events_count INTEGER DEFAULT 0,
                blocked_count INTEGER DEFAULT 0,
                permissions TEXT DEFAULT '["*"]',
                port INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                event_id TEXT,
                agent_id TEXT,
                layer TEXT,
                event_type TEXT,
                action TEXT,
                verdict TEXT,
                threat_level TEXT,
                message TEXT,
                details TEXT,
                tool_name TEXT,
                tool_args TEXT,
                latency_ms REAL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_events_agent ON events(agent_id);
            CREATE INDEX IF NOT EXISTS idx_events_layer ON events(layer);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS conversations (
                conversation_id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                title TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                tool_calls TEXT DEFAULT '[]',
                security_events TEXT DEFAULT '[]',
                FOREIGN KEY (conversation_id) REFERENCES conversations(conversation_id)
            );
        """)
        c.commit()

    # ── Agent Registry ───────────────────────────────────────────────

    def ensure_studio_agent(self):
        """Upsert the built-in studio agent."""
        c = self._conn()
        now = _now_iso()
        c.execute("""
            INSERT INTO agents (agent_id, name, framework, agent_type, created_at, last_heartbeat, status, permissions)
            VALUES ('studio', 'Demo Agent', 'built-in', 'demo', ?, ?, 'online', '["*"]')
            ON CONFLICT(agent_id) DO UPDATE SET status='online', last_heartbeat=?
        """, (now, now, now))
        c.commit()

    def get_agents(self) -> list[dict[str, Any]]:
        c = self._conn()
        rows = c.execute("SELECT * FROM agents ORDER BY created_at").fetchall()
        agents = []
        for r in rows:
            agent = dict(r)
            agent["permissions"] = json.loads(agent.get("permissions", "[]"))
            agent["layers_enabled"] = json.loads(agent.get("layers_enabled", "[]"))
            agent["tools_enabled"] = json.loads(agent.get("tools_enabled", "[]"))
            # Mark non-studio agents offline if no heartbeat for 60s
            if agent["agent_id"] != "studio":
                try:
                    hb = datetime.datetime.fromisoformat(agent["last_heartbeat"])
                    now = datetime.datetime.now(datetime.timezone.utc)
                    if (now - hb).total_seconds() > 60:
                        agent["status"] = "offline"
                except (ValueError, TypeError):
                    agent["status"] = "offline"
            agents.append(agent)
        return agents

    def register_agent(
        self,
        agent_id: str,
        framework: str = "custom",
        agent_type: str = "general",
        permissions: list[str] | None = None,
        name: str = "",
        system_prompt: str = "",
        layers_enabled: list[int] | None = None,
        tools_enabled: list[str] | None = None,
        provider: str = "ollama",
        provider_model: str = "",
        port: int = 0,
    ) -> dict[str, Any]:
        c = self._conn()
        now = _now_iso()
        c.execute("""
            INSERT INTO agents (agent_id, name, framework, agent_type, system_prompt,
                               layers_enabled, tools_enabled, provider, provider_model,
                               created_at, last_heartbeat, status, permissions, port)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'online', ?, ?)
            ON CONFLICT(agent_id) DO UPDATE SET
                framework=excluded.framework, agent_type=excluded.agent_type,
                last_heartbeat=excluded.last_heartbeat, status='online',
                permissions=excluded.permissions, port=excluded.port,
                name=CASE WHEN excluded.name != '' THEN excluded.name ELSE agents.name END,
                system_prompt=CASE WHEN excluded.system_prompt != '' THEN excluded.system_prompt ELSE agents.system_prompt END
        """, (
            agent_id, name or agent_id, framework, agent_type, system_prompt,
            json.dumps(layers_enabled or []), json.dumps(tools_enabled or []),
            provider, provider_model, now, now,
            json.dumps(permissions or ["scan.*", "read.*", "search.*"]),
            port,
        ))
        c.commit()
        return {"agent_id": agent_id, "registered_at": now}

    def update_heartbeat(self, agent_id: str):
        c = self._conn()
        c.execute("UPDATE agents SET last_heartbeat=?, status='online' WHERE agent_id=?",
                  (_now_iso(), agent_id))
        c.commit()

    def increment_event_count(self, agent_id: str, blocked: bool = False):
        c = self._conn()
        if blocked:
            c.execute("UPDATE agents SET events_count=events_count+1, blocked_count=blocked_count+1 WHERE agent_id=?", (agent_id,))
        else:
            c.execute("UPDATE agents SET events_count=events_count+1 WHERE agent_id=?", (agent_id,))
        c.commit()

    def unregister_agent(self, agent_id: str):
        c = self._conn()
        c.execute("DELETE FROM agents WHERE agent_id=?", (agent_id,))
        c.commit()

    def get_agent_port(self, agent_id: str) -> int:
        c = self._conn()
        row = c.execute("SELECT port FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
        return row["port"] if row else 0

    # ── Event Storage ────────────────────────────────────────────────

    def store_event(self, entry: dict[str, Any]):
        c = self._conn()
        c.execute("""
            INSERT INTO events (timestamp, event_id, agent_id, layer, event_type,
                               action, verdict, threat_level, message, details,
                               tool_name, tool_args, latency_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            entry.get("_timestamp", entry.get("timestamp", 0)),
            entry.get("event_id", ""),
            entry.get("agent_id", ""),
            entry.get("layer", ""),
            entry.get("event_type", entry.get("type", "")),
            entry.get("action", ""),
            entry.get("verdict", ""),
            entry.get("threat_level", ""),
            entry.get("message", ""),
            json.dumps(entry.get("details", entry.get("params", {})), default=str),
            entry.get("tool_name", ""),
            json.dumps(entry.get("tool_args", {}), default=str),
            entry.get("latency_ms", entry.get("processing_time_ms", 0)),
        ))
        c.commit()

    def get_events(self, limit: int = 100, agent_id: str | None = None,
                   layer: str | None = None, verdict: str | None = None) -> list[dict[str, Any]]:
        c = self._conn()
        query = "SELECT * FROM events WHERE 1=1"
        params: list[Any] = []
        if agent_id:
            query += " AND agent_id=?"
            params.append(agent_id)
        if layer:
            query += " AND layer=?"
            params.append(layer)
        if verdict:
            query += " AND verdict=?"
            params.append(verdict)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        rows = c.execute(query, params).fetchall()
        return [dict(r) for r in reversed(rows)]

    def get_events_summary(self) -> dict[str, Any]:
        c = self._conn()
        total = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        blocked = c.execute("SELECT COUNT(*) FROM events WHERE verdict='deny'").fetchone()[0]
        allowed = c.execute("SELECT COUNT(*) FROM events WHERE verdict='allow'").fetchone()[0]
        by_layer = {}
        for row in c.execute("SELECT layer, COUNT(*) as cnt FROM events WHERE layer != '' GROUP BY layer").fetchall():
            by_layer[row["layer"]] = row["cnt"]
        return {"total": total, "blocked": blocked, "allowed": allowed, "by_layer": by_layer}

    # ── Settings ─────────────────────────────────────────────────────

    def get_setting(self, key: str, default: str = "") -> str:
        c = self._conn()
        row = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str):
        c = self._conn()
        c.execute("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                  (key, value))
        c.commit()

    # ── Conversation History ──────────────────────────────────────────

    def create_conversation(self, agent_id: str, title: str = "") -> str:
        """Create a new conversation and return its ID."""
        import uuid
        conversation_id = str(uuid.uuid4())
        now = _now_iso()
        c = self._conn()
        c.execute(
            "INSERT INTO conversations (conversation_id, agent_id, title, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (conversation_id, agent_id, title or f"Chat {now[:10]}", now, now),
        )
        c.commit()
        return conversation_id

    def get_conversations(self, agent_id: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        """Return conversations ordered by most recently updated."""
        c = self._conn()
        if agent_id:
            rows = c.execute(
                "SELECT * FROM conversations WHERE agent_id=? ORDER BY updated_at DESC LIMIT ?",
                (agent_id, limit),
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT * FROM conversations ORDER BY updated_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_messages(self, conversation_id: str) -> list[dict[str, Any]]:
        """Return all messages in a conversation ordered by insertion."""
        c = self._conn()
        rows = c.execute(
            "SELECT * FROM messages WHERE conversation_id=? ORDER BY id ASC",
            (conversation_id,),
        ).fetchall()
        result = []
        for r in rows:
            msg = dict(r)
            msg["tool_calls"] = json.loads(msg.get("tool_calls") or "[]")
            msg["security_events"] = json.loads(msg.get("security_events") or "[]")
            result.append(msg)
        return result

    def append_message(
        self,
        conversation_id: str,
        role: str,
        content: str,
        tool_calls: list | None = None,
        security_events: list | None = None,
    ) -> int:
        """Append a message to a conversation and touch updated_at."""
        now = _now_iso()
        c = self._conn()
        cursor = c.execute(
            "INSERT INTO messages (conversation_id, role, content, timestamp, tool_calls, security_events) VALUES (?, ?, ?, ?, ?, ?)",
            (
                conversation_id, role, content, now,
                json.dumps(tool_calls or []),
                json.dumps(security_events or []),
            ),
        )
        c.execute("UPDATE conversations SET updated_at=? WHERE conversation_id=?", (now, conversation_id))
        c.commit()
        return cursor.lastrowid or 0

    def delete_conversation(self, conversation_id: str):
        c = self._conn()
        c.execute("DELETE FROM messages WHERE conversation_id=?", (conversation_id,))
        c.execute("DELETE FROM conversations WHERE conversation_id=?", (conversation_id,))
        c.commit()

