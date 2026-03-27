"""AgentWorkspace — Per-agent SQLite database and sandboxed file I/O.

Each agent gets:
  ~/.agentarmor/agents/<agent_id>/agent.db    — SQLite database
  ~/.agentarmor/agents/<agent_id>/workspace/   — sandboxed file I/O
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any

AGENTARMOR_DIR = Path.home() / ".agentarmor"
AGENTS_DIR = AGENTARMOR_DIR / "agents"


class PathTraversalError(Exception):
    """Raised when a file path escapes the agent's workspace sandbox."""
    pass


def _scan_for_write_injection(text: str) -> bool:
    """Returns True if an injection pattern of severity >= 8 is found."""
    import agentarmor.layers.ingestion.scanner as l1_scanner
    normalized, _ = l1_scanner.normalize_and_disarm(text)
    for cat, patterns in l1_scanner.L1_PATTERNS.items():
        if l1_scanner.CATEGORY_SEVERITY[cat] >= 8:
            for pat in patterns:
                if pat.search(normalized):
                    return True
    return False

class AgentWorkspace:
    """Manages per-agent database and sandboxed filesystem."""

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self._base = AGENTS_DIR / agent_id
        self._db_path = self._base / "agent.db"
        self._workspace = self._base / "workspace"
        self._ensure_dirs()

    def _ensure_dirs(self):
        self._base.mkdir(parents=True, exist_ok=True)
        self._workspace.mkdir(parents=True, exist_ok=True)

    # ── Database ─────────────────────────────────────────────────────

    def get_db(self) -> sqlite3.Connection:
        """Return a connection to the agent's SQLite database."""
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def execute_sql(self, sql: str) -> str:
        """Execute SQL against the agent's database. Returns JSON result."""
        sql_stripped = sql.strip()
        sql_lower = sql_stripped.lower()

        conn = self.get_db()
        try:
            cursor = conn.execute(sql_stripped)

            if sql_lower.startswith("select"):
                rows = cursor.fetchall()
                result = [dict(r) for r in rows]
                return json.dumps(result, indent=2, default=str)

            elif sql_lower.startswith(("insert", "update", "delete")):
                if sql_lower.startswith(("insert", "update")) and _scan_for_write_injection(sql):
                    return json.dumps({
                        "status": "error",
                        "message": "Error: AgentArmor L1 blocked SQL execution — injection pattern detected in data payload"
                    }, indent=2)
                conn.commit()
                return json.dumps({
                    "status": "success",
                    "operation": sql_lower.split()[0].upper(),
                    "rows_affected": cursor.rowcount,
                }, indent=2)

            elif sql_lower.startswith(("create", "alter")):
                conn.commit()
                return json.dumps({
                    "status": "success",
                    "operation": "DDL",
                    "message": f"Statement executed successfully",
                }, indent=2)

            elif sql_lower.startswith("drop"):
                conn.commit()
                return json.dumps({
                    "status": "success",
                    "operation": "DROP",
                    "message": "Table dropped",
                }, indent=2)

            else:
                conn.commit()
                return json.dumps({
                    "status": "success",
                    "message": f"Query executed, {cursor.rowcount} rows affected",
                }, indent=2)

        except sqlite3.Error as e:
            return json.dumps({"status": "error", "message": str(e)}, indent=2)
        finally:
            conn.close()

    # ── Sandboxed File I/O ───────────────────────────────────────────

    def validate_path(self, requested_path: str) -> Path:
        """Resolve a path and ensure it stays within the agent's workspace.

        Prevents path traversal (../../etc/shadow) by resolving to absolute
        and asserting the result starts with the workspace root.
        """
        # Strip leading / so paths like "/notes.txt" resolve inside workspace
        clean = requested_path.lstrip("/").lstrip("\\")
        resolved = (self._workspace / clean).resolve()
        workspace_resolved = self._workspace.resolve()

        if not str(resolved).startswith(str(workspace_resolved)):
            raise PathTraversalError(
                f"Path traversal blocked: '{requested_path}' resolves outside workspace"
            )
        return resolved

    def file_read(self, path: str, max_bytes: int = 32_768) -> str:
        """Read a file from the agent's workspace."""
        try:
            resolved = self.validate_path(path)
        except PathTraversalError as e:
            return f"Error: {e}"

        if not resolved.exists():
            return f"Error: File '{path}' not found in workspace"
        if not resolved.is_file():
            return f"Error: '{path}' is not a file"

        try:
            content = resolved.read_text(encoding="utf-8", errors="replace")
            if len(content) > max_bytes:
                content = content[:max_bytes] + f"\n... [truncated at {max_bytes} bytes]"
            return content
        except Exception as e:
            return f"Error reading file: {e}"

    def file_write(self, path: str, content: str) -> str:
        """Write a file to the agent's workspace."""
        if _scan_for_write_injection(content):
            return "Error: AgentArmor L1 blocked file write — injection pattern detected in content"
            
        try:
            resolved = self.validate_path(path)
        except PathTraversalError as e:
            return f"Error: {e}"

        try:
            resolved.parent.mkdir(parents=True, exist_ok=True)
            resolved.write_text(content, encoding="utf-8")
            return f"Successfully wrote {len(content)} bytes to {path}"
        except Exception as e:
            return f"Error writing file: {e}"

    def file_delete(self, path: str) -> str:
        """Delete a file from the agent's workspace."""
        try:
            resolved = self.validate_path(path)
        except PathTraversalError as e:
            return f"Error: {e}"

        if not resolved.exists():
            return f"Error: File '{path}' not found in workspace"

        try:
            resolved.unlink()
            return f"Deleted {path}"
        except Exception as e:
            return f"Error deleting file: {e}"

    def list_files(self, path: str = ".") -> str:
        """List files in the agent's workspace directory."""
        try:
            resolved = self.validate_path(path)
        except PathTraversalError as e:
            return f"Error: {e}"

        if not resolved.exists():
            return f"Error: Directory '{path}' not found"
        if not resolved.is_dir():
            return f"Error: '{path}' is not a directory"

        entries = []
        for item in sorted(resolved.iterdir()):
            rel = item.relative_to(self._workspace.resolve())
            if item.is_dir():
                entries.append(f"  [dir]  {rel}/")
            else:
                size = item.stat().st_size
                entries.append(f"  [file] {rel} ({size} bytes)")

        if not entries:
            return "Workspace is empty."
        return f"Workspace contents ({len(entries)} items):\n" + "\n".join(entries)

    @property
    def workspace_path(self) -> Path:
        return self._workspace

    @property
    def db_path(self) -> Path:
        return self._db_path


# Module-level cache to avoid recreating workspaces
_workspace_cache: dict[str, AgentWorkspace] = {}


def get_workspace(agent_id: str) -> AgentWorkspace:
    """Get or create an AgentWorkspace for the given agent."""
    if agent_id not in _workspace_cache:
        _workspace_cache[agent_id] = AgentWorkspace(agent_id)
    return _workspace_cache[agent_id]
