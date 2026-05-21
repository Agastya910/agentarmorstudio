"""AgentArmor Studio — FastAPI sidecar server.

Launched by the Tauri shell on app start. Binds to a random available port
on 127.0.0.1 and writes the port number to a temp file so the frontend
can discover it via the `get_sidecar_port` Tauri command.
"""

from __future__ import annotations

import atexit
import datetime
import json
import os
import secrets
import signal
import socket
import sys
import tempfile
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx

# Load .env if python-dotenv is available
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / ".env")
except ImportError:
    pass

import uvicorn
from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from agentarmor import AgentArmor, ArmorConfig
from agentarmor.core.types import AgentEvent, LayerResult, SecurityVerdict, ThreatLevel
from agentarmor.layers.context.assembler import (
    L3ContextLayer,
    get_and_clear_l3_events,
)
from agentarmor.layers.planning.l4_planning import (
    L4PlanningLayer,
    _describe_block_reason,
    _summarize_args,
)
from agentarmor.layers.execution.l5_execution import (
    L5ExecutionLayer,
    NetworkPolicy,
)
from agentarmor.layers.output.filter import L6OutputLayer

# Local sidecar modules (imported via sys.path — sidecar dir is the run root)
try:
    import l1_tools
    from builder.runner import deploy_agent, resume_all_agents
    from studio_db import StudioDB
    from workspace import PathTraversalError, get_workspace
except ImportError:
    from sidecar import l1_tools
    from sidecar.builder.runner import resume_all_agents
    from sidecar.studio_db import StudioDB
    from sidecar.workspace import get_workspace

# ---------------------------------------------------------------------------
# Port discovery
# ---------------------------------------------------------------------------

PORT_FILE = Path(tempfile.gettempdir()) / "agentarmor_sidecar.port"


def _get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _write_port(port: int) -> None:
    PORT_FILE.write_text(str(port))


def _cleanup_port_file() -> None:
    try:
        PORT_FILE.unlink(missing_ok=True)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# AgentArmor instance (shared across requests)
# ---------------------------------------------------------------------------

armor = AgentArmor(config=ArmorConfig())

# Auto-register "studio" as a trusted agent so L8 Identity doesn't block it.
armor.l8_identity.register_agent(
    agent_id="studio",
    agent_type="studio",
    owner="AgentArmor Studio",
    permissions={"*"},
    credential_ttl=0,
)

# ---------------------------------------------------------------------------
# L3 Context Layer — persists across requests for GoalLock + CanaryVault state
# ---------------------------------------------------------------------------

_l3_agent_config = {
    "system_prompt": "You are a helpful assistant with access to tools.",
    "tools": list(TOOL_REGISTRY.keys()) if 'TOOL_REGISTRY' in dir() else [],
}
# Deferred initialization — TOOL_REGISTRY isn't available yet at module scope.
# The actual instance is created lazily in _get_l3_layer().
_l3_layer: L3ContextLayer | None = None
_l3_turn_counter: dict[str, int] = {}  # conversation_id -> turn count


def _get_l3_layer() -> L3ContextLayer:
    """Lazy-init the L3 layer so TOOL_REGISTRY is available."""
    global _l3_layer
    if _l3_layer is None:
        _l3_layer = L3ContextLayer(
            agent_id="studio",
            agent_config={
                "system_prompt": "You are a helpful assistant with access to tools. Use them when needed to answer questions, look up information, manage files, and complete tasks.",
                "tools": list(TOOL_REGISTRY.keys()),
            },
        )
    return _l3_layer


def _next_turn(conversation_id: str) -> int:
    """Increment and return the turn counter for a conversation."""
    _l3_turn_counter[conversation_id] = _l3_turn_counter.get(conversation_id, 0) + 1
    return _l3_turn_counter[conversation_id]


# ---------------------------------------------------------------------------
# L4 Planning Layer — persists across requests for ActionChainTracker state
# ---------------------------------------------------------------------------

_l4_layer: L4PlanningLayer | None = None


def _get_l4_layer() -> L4PlanningLayer:
    """Lazy-init the L4 layer."""
    global _l4_layer
    if _l4_layer is None:
        _l4_layer = L4PlanningLayer(agent_id="studio")
    return _l4_layer


# ---------------------------------------------------------------------------
# L5 Execution Layer — persists across requests for rate limiter + audit state
# ---------------------------------------------------------------------------

_l5_layer: L5ExecutionLayer | None = None


def _get_l5_layer(agent_id: str | None = None) -> L5ExecutionLayer:
    """Lazy-init the L5 layer."""
    global _l5_layer
    # In a full multi-agent setup, we should cache these per-agent.
    # We will initialize a generic one when no agent_id is passed,
    # or build a specific one when an agent_id is passed if we want.
    # For now, Studio uses its global settings, but agent execution uses local db values.
    
    allow_http = studio_db.get_setting("network_allow_http", "False") == "True"
    max_payload = int(studio_db.get_setting("network_max_payload", "1024")) * 1024
    
    domain_allowlist = []
    domain_blocklist = [
        "metadata.google.internal",
        "metadata.internal",
        "*.internal",
        "*.local",
    ]
    
    if agent_id and agent_id != "studio":
        # Get per-agent config
        agents = studio_db.get_agents()
        agent = next((a for a in agents if a["agent_id"] == agent_id), None)
        if agent and "network_policy" in agent:
            np = agent["network_policy"]
            if np.get("isolation_level") == "ISOLATED":
                # Override to block everything
                domain_blocklist = ["*"]
            elif np.get("isolation_level") == "OPEN":
                # No allowlist, everything allowed except blocklist
                pass
            else: # ALLOWLIST
                domain_allowlist = [d.strip() for d in np.get("domain_allowlist", "").split(",") if d.strip()]
            
            # Agent-specific blocklist is appended to the global basic blocklist
            if np.get("blocked_domains"):
                custom_blocks = [d.strip() for d in np.get("blocked_domains").split(",") if d.strip()]
                domain_blocklist.extend(custom_blocks)
    
    policy = NetworkPolicy(
        allow_http=allow_http,
        max_outbound_payload_bytes=max_payload,
        dns_rebinding_protection=True,
        domain_allowlist=domain_allowlist,
        domain_blocklist=domain_blocklist
    )
    
    if agent_id:
        return L5ExecutionLayer(agent_id=agent_id, network_policy=policy)
        
    if _l5_layer is None:
        _l5_layer = L5ExecutionLayer(
            agent_id="studio",
            network_policy=policy,
        )
    return _l5_layer


# ---------------------------------------------------------------------------
# L6 Output Layer — persists across requests for Semantic Exfiltration context
# ---------------------------------------------------------------------------

_l6_layer: L6OutputLayer | None = None


def _get_l6_layer() -> L6OutputLayer:
    """Lazy-init the L6 layer."""
    global _l6_layer
    if _l6_layer is None:
        _l6_layer = L6OutputLayer(
            agent_id="studio",
            enable_pii_scan=True,
            enable_harmful_scan=True,
        )
    return _l6_layer


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

OLLAMA_BASE = "http://localhost:11434"


class ScanRequest(BaseModel):
    text: str
    agent_id: str = "studio"


class OllamaAgentRequest(BaseModel):
    agent_id: str = "studio"
    model: str
    system_prompt: str = "You are a helpful assistant with access to tools. Use them when needed to answer questions, look up information, manage files, and complete tasks."
    user_message: str
    layers_enabled: list[int] = [1, 2, 3, 4, 5, 6, 7, 8]
    conversation_history: list[dict[str, Any]] = []


class AgentRegisterRequest(BaseModel):
    agent_id: str
    framework: str = "custom"  # mcp | langchain | openai | custom
    agent_type: str = "general"
    permissions: list[str] = ["scan.*", "read.*", "search.*"]


class AgentEventRequest(BaseModel):
    action: str
    event_type: str = "tool_call"
    verdict: str = "allow"  # allow | deny | escalate
    threat_level: str = "none"  # none | low | medium | high | critical
    message: str = ""
    params: dict[str, Any] = {}


class BuilderDeployRequest(BaseModel):
    name: str
    system_prompt: str
    provider: str
    provider_model: str = ""
    provider_api_key: str = ""
    layers: list[int]
    tools: list[str]
    isolation_level: str = "ALLOWLIST"
    domain_allowlist: str = ""
    blocked_domains: str = ""


# ---------------------------------------------------------------------------
# Studio API Key — persisted in ~/.agentarmor/studio.key
# ---------------------------------------------------------------------------

AGENTARMOR_DIR = Path.home() / ".agentarmor"


def _load_or_create_api_key() -> str:
    """Load existing Studio API key or generate a new one."""
    AGENTARMOR_DIR.mkdir(parents=True, exist_ok=True)
    key_file = AGENTARMOR_DIR / "studio.key"
    if key_file.exists():
        key = key_file.read_text().strip()
        if len(key) >= 32:
            return key
    # Generate a new key: aa-sk-<48 hex chars>
    key = f"aa-sk-{secrets.token_hex(24)}"
    key_file.write_text(key)
    return key


STUDIO_API_KEY = _load_or_create_api_key()


def _validate_api_key(authorization: str | None) -> None:
    """Validate the Authorization header against the Studio API key."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header. Use: Authorization: Bearer <studio-api-key>")
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid Authorization format. Use: Bearer <studio-api-key>")
    if parts[1] != STUDIO_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key. Get your Studio API key from Settings.")


# ---------------------------------------------------------------------------
# Persistent storage — agent registry, events, settings
# ---------------------------------------------------------------------------

studio_db = StudioDB()
studio_db.ensure_studio_agent()

# Ensure studio agent workspace exists
get_workspace("studio")


# ---------------------------------------------------------------------------
# Tool Registry — real implementations that exercise all AgentArmor layers
# ---------------------------------------------------------------------------


def tool_file_read(path: str, _agent_id: str = "studio") -> str:
    """Read a file from the agent's sandboxed workspace."""
    ws = get_workspace(_agent_id)
    return ws.file_read(path)


def tool_file_write(path: str, content: str, _agent_id: str = "studio") -> str:
    """Write a file to the agent's sandboxed workspace."""
    ws = get_workspace(_agent_id)
    return ws.file_write(path, content)


def tool_file_delete(path: str, _agent_id: str = "studio") -> str:
    """Delete a file from the agent's sandboxed workspace."""
    ws = get_workspace(_agent_id)
    return ws.file_delete(path)


def tool_web_search(query: str) -> str:
    """Real web search via Tavily API. Falls back to DuckDuckGo scraping if no key."""
    tavily_key = studio_db.get_setting("tavily_api_key", os.environ.get("TAVILY_API_KEY", ""))
    if tavily_key:
        try:
            from tavily import TavilyClient
            client = TavilyClient(api_key=tavily_key)
            resp = client.search(query, max_results=5)
            results = resp.get("results", [])
            formatted = []
            for i, r in enumerate(results, 1):
                formatted.append(f"{i}. {r.get('title', 'No title')}\n   URL: {r.get('url', '')}\n   {r.get('content', '')[:300]}")
            return f"Search results for '{query}':\n\n" + "\n\n".join(formatted)
        except ImportError:
            return (
                f"Search results for '{query}':\n"
                "(tavily-python not installed — run: pip install tavily-python)\n"
                "Set TAVILY_API_KEY in Settings to enable real web search."
            )
        except Exception as e:
            return f"Web search error: {e}\nQuery was: {query}"
    else:
        return (
            f"Search results for '{query}':\n"
            "Web search requires a Tavily API key.\n"
            "Go to Settings → External APIs → enter your TAVILY_API_KEY (free at tavily.com).\n"
            "Without it, I cannot search the web."
        )


def tool_web_fetch(url: str) -> str:
    """Fetch real content from a URL via httpx."""
    try:
        with httpx.Client(timeout=15.0, follow_redirects=True) as client:
            resp = client.get(url, headers={"User-Agent": "AgentArmor-Studio/1.0"})
            resp.raise_for_status()
            content = resp.text
            # Strip to text if HTML
            if "<html" in content[:200].lower():
                try:
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(content, "html.parser")
                    for tag in soup(["script", "style", "nav", "header", "footer"]):
                        tag.decompose()
                    content = soup.get_text(separator="\n", strip=True)
                except ImportError:
                    pass
            # Truncate
            if len(content) > 4000:
                content = content[:4000] + "\n... [truncated]"
            return f"Content from {url}:\n\n{content}"
    except httpx.HTTPStatusError as e:
        return f"HTTP {e.response.status_code} fetching {url}"
    except Exception as e:
        return f"Error fetching {url}: {e}"


def tool_db_query(sql: str, _agent_id: str = "studio") -> str:
    """Execute SQL against the agent's own SQLite database."""
    ws = get_workspace(_agent_id)
    return ws.execute_sql(sql)


def tool_send_email(to: str, subject: str, body: str) -> str:
    """Simulated email send — logs the attempt. Set MAILTRAP_TOKEN to enable real capture."""
    return f"[SIMULATED] Email to {to} | Subject: {subject}\nBody preview: {body[:200]}\nNote: Set MAILTRAP_TOKEN in Settings to capture real emails."


def tool_run_code(language: str, code: str) -> str:
    """Run code in an E2B sandbox. Requires E2B_API_KEY in Settings."""
    e2b_key = studio_db.get_setting("e2b_api_key", os.environ.get("E2B_API_KEY", ""))
    if e2b_key:
        try:
            from e2b_code_interpreter import Sandbox
            with Sandbox(api_key=e2b_key) as sbx:
                result = sbx.run_code(code)
                output = []
                for log in result.logs.stdout:
                    output.append(log)
                for log in result.logs.stderr:
                    output.append(f"[stderr] {log}")
                if result.error:
                    output.append(f"[error] {result.error.name}: {result.error.value}")
                return f"Code execution ({language}) via E2B sandbox:\n" + "\n".join(output) if output else "(no output)"
        except ImportError:
            pass
        except Exception as e:
            return f"E2B execution error: {e}"
    return (
        "Code execution is not available.\n"
        "To enable code execution, set your E2B_API_KEY in Settings → External APIs.\n"
        "Get a free key at https://e2b.dev"
    )


def tool_knowledge_search(query: str, _agent_id: str = "studio") -> str:
    """Search the agent's workspace files for content matching the query."""
    ws = get_workspace(_agent_id)
    query_lower = query.lower()
    matches = []
    try:
        for f in ws.workspace_path.rglob("*"):
            if f.is_file() and f.stat().st_size < 100_000:
                try:
                    text = f.read_text(encoding="utf-8", errors="replace")
                    if query_lower in text.lower():
                        snippet = text[:500]
                        matches.append({"file": str(f.relative_to(ws.workspace_path)), "snippet": snippet})
                except Exception:
                    pass
    except Exception:
        pass
    if not matches:
        return json.dumps({"results": [], "message": f"No workspace files matched '{query}'"}, indent=2)
    return json.dumps({"results": matches[:5], "total": len(matches)}, indent=2)


def tool_calendar_create(title: str, date: str, attendees: str = "") -> str:
    """Create a calendar event. (Simulated — integrate Google Calendar via Settings for real events.)"""
    event_id = secrets.token_hex(4)
    return json.dumps({
        "status": "created",
        "event_id": event_id,
        "title": title,
        "date": date,
        "attendees": attendees.split(",") if attendees else [],
        "note": "Simulated — set GOOGLE_CALENDAR_TOKEN in Settings for real events.",
    }, indent=2)


def tool_api_call(method: str, url: str, body: str = "") -> str:
    """Make a real HTTP request. Gated by L5 NetworkPolicy before execution."""
    try:
        with httpx.Client(timeout=10.0) as client:
            req_body = body.encode() if body else None
            resp = client.request(method.upper(), url, content=req_body,
                                  headers={"Content-Type": "application/json"} if body else {})
            response_text = resp.text[:2000]
            return f"API {method.upper()} {url} → {resp.status_code}\nResponse:\n{response_text}"
    except Exception as e:
        return f"API call failed: {e}"


def tool_delegate_to_agent(agent_id: str, message: str) -> str:
    """Delegate a task to another registered agent via inter-agent protocol."""
    agents = studio_db.get_agents()
    target = next((a for a in agents if a["agent_id"] == agent_id), None)
    if not target:
        return f"Error: Agent '{agent_id}' not found in registry."
    if target["status"] != "online":
        return f"Error: Agent '{agent_id}' is offline."
    port = target.get("port", 0)
    if port:
        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.post(f"http://127.0.0.1:{port}/chat",
                                   json={"message": message}, timeout=10.0)
                return f"Delegated to '{agent_id}': {resp.json().get('response', resp.text[:500])}"
        except Exception as e:
            return f"Delegation to '{agent_id}' failed: {e}"
    return f"Delegated to '{agent_id}': {message}\nResponse: 'Task received.' (agent port not yet registered)"


# --- Tool metadata for Ollama function calling ---

TOOL_REGISTRY: dict[str, dict[str, Any]] = {
    "file_read": {
        "fn": tool_file_read, "action": "file.read",
        "description": "Read content from a file on the filesystem",
        "parameters": {"type": "object", "properties": {"path": {"type": "string", "description": "File path to read, e.g. /home/user/config.yaml"}}, "required": ["path"]},
    },
    "file_write": {
        "fn": tool_file_write, "action": "file.write",
        "description": "Write content to a file on the filesystem",
        "parameters": {"type": "object", "properties": {"path": {"type": "string", "description": "File path"}, "content": {"type": "string", "description": "Content to write"}}, "required": ["path", "content"]},
    },
    "file_delete": {
        "fn": tool_file_delete, "action": "file.delete",
        "description": "Delete a file from the filesystem",
        "parameters": {"type": "object", "properties": {"path": {"type": "string", "description": "File path to delete"}}, "required": ["path"]},
    },
    "web_search": {
        "fn": tool_web_search, "action": "web.search",
        "description": "Search the web for information",
        "parameters": {"type": "object", "properties": {"query": {"type": "string", "description": "Search query"}}, "required": ["query"]},
    },
    "web_fetch": {
        "fn": tool_web_fetch, "action": "web.fetch",
        "description": "Fetch content from a URL",
        "parameters": {"type": "object", "properties": {"url": {"type": "string", "description": "URL to fetch"}}, "required": ["url"]},
    },
    "db_query": {
        "fn": tool_db_query, "action": "database.query",
        "description": "Execute a SQL query against the database",
        "parameters": {"type": "object", "properties": {"sql": {"type": "string", "description": "SQL query"}}, "required": ["sql"]},
    },
    "send_email": {
        "fn": tool_send_email, "action": "email.send",
        "description": "Send an email to a recipient",
        "parameters": {"type": "object", "properties": {"to": {"type": "string", "description": "Recipient email"}, "subject": {"type": "string", "description": "Subject"}, "body": {"type": "string", "description": "Body"}}, "required": ["to", "subject", "body"]},
    },
    "run_code": {
        "fn": tool_run_code, "action": "code.execute",
        "description": "Execute code in a sandboxed environment",
        "parameters": {"type": "object", "properties": {"language": {"type": "string", "description": "Language (python, javascript, bash)"}, "code": {"type": "string", "description": "Code to execute"}}, "required": ["language", "code"]},
    },
    "knowledge_search": {
        "fn": tool_knowledge_search, "action": "knowledge.search",
        "description": "Search the internal knowledge base for documents and policies",
        "parameters": {"type": "object", "properties": {"query": {"type": "string", "description": "Search query"}}, "required": ["query"]},
    },
    "calendar_create": {
        "fn": tool_calendar_create, "action": "calendar.create",
        "description": "Create a new calendar event",
        "parameters": {"type": "object", "properties": {"title": {"type": "string", "description": "Event title"}, "date": {"type": "string", "description": "Date/time"}, "attendees": {"type": "string", "description": "Comma-separated emails"}}, "required": ["title", "date"]},
    },
    "api_call": {
        "fn": tool_api_call, "action": "api.request",
        "description": "Make an HTTP API request",
        "parameters": {"type": "object", "properties": {"method": {"type": "string", "description": "HTTP method"}, "url": {"type": "string", "description": "URL"}, "body": {"type": "string", "description": "Request body"}}, "required": ["method", "url"]},
    },
    "delegate_to_agent": {
        "fn": tool_delegate_to_agent, "action": "agent.delegate",
        "description": "Delegate a task to another AI agent",
        "parameters": {"type": "object", "properties": {"agent_id": {"type": "string", "description": "Target agent ID"}, "message": {"type": "string", "description": "Task description"}}, "required": ["agent_id", "message"]},
    },
}

OLLAMA_TOOLS = [
    {"type": "function", "function": {"name": n, "description": m["description"], "parameters": m["parameters"]}}
    for n, m in TOOL_REGISTRY.items()
]

LAYER_MAP = {
    1: "l1_ingestion", 2: "l2_storage", 3: "l3_context",
    4: "l4_planning", 5: "l5_execution", 7: "l7_interagent", 8: "l8_identity",
}


# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------

async def _run_layer(layer_num: int, event: AgentEvent, enabled: set[int]) -> LayerResult | None:
    """Run a single layer if enabled."""
    if layer_num not in enabled:
        return None
    attr = LAYER_MAP.get(layer_num)
    if not attr:
        return None
    layer = getattr(armor, attr, None)
    if layer is None:
        return None
    result = await layer.execute(event)
    armor.audit.log_layer_result(event, result)
    return result


async def _security_check_tool_call(
    tool_name: str, tool_args: dict[str, Any], enabled: set[int],
    session_id: str = "studio-default",
) -> tuple[bool, str | None, list[dict[str, Any]], float]:
    """Run L4/L5/L8/L7 on a tool call. Returns (blocked, blocked_by, events, overhead_ms)."""
    action = TOOL_REGISTRY.get(tool_name, {}).get("action", tool_name)
    events: list[dict[str, Any]] = []
    overhead = 0.0

    # === L4 Planning Layer — multi-dimensional risk evaluation ===
    if 4 in enabled:
        t = time.perf_counter()
        l4 = _get_l4_layer()
        l4_result = l4.evaluate(tool_name, tool_args, session_id)
        overhead += (time.perf_counter() - t) * 1000

        l4_event = {
            "layer": l4_result["layer"],
            "verdict": l4_result["verdict"],
            "threat_level": l4_result["threat_level"],
            "message": (
                f"L4 risk={l4_result['composite_score']:.2f} "
                f"[verb={l4_result['dimensions']['verb_score']:.2f} "
                f"res={l4_result['dimensions']['resource_score']:.2f} "
                f"rev={l4_result['dimensions']['reversibility_score']:.2f} "
                f"inj={l4_result['dimensions']['injection_score']:.2f} "
                f"chain={l4_result['dimensions']['chain_score']:.2f}]"
            ),
            "details": l4_result,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        events.append(l4_event)
        studio_db.store_event({
            **l4_event, "agent_id": "studio", "_timestamp": time.time(),
        })

        if l4_result["verdict"] == "block":
            return True, "L4_Planning", events, overhead

    # === Pipeline layers (L5 sandbox, L8 identity) ===
    tool_event = AgentEvent(
        agent_id="studio", event_type="tool_call", action=action,
        params=tool_args, input_data=str(tool_args),
    )
    armor.audit.log_event(tool_event)

    for layer_num in [5, 8]:
        t = time.perf_counter()
        result = await _run_layer(layer_num, tool_event, enabled)
        overhead += (time.perf_counter() - t) * 1000
        if result:
            events.append({
                "layer": result.layer, "verdict": result.verdict.value,
                "threat_level": result.threat_level.value, "message": result.message,
                "details": result.details,
            })
            if result.is_blocked:
                return True, result.layer, events, overhead

    # L7 only for agent delegation
    if action == "agent.delegate":
        t = time.perf_counter()
        result = await _run_layer(7, tool_event, enabled)
        overhead += (time.perf_counter() - t) * 1000
        if result:
            events.append({
                "layer": result.layer, "verdict": result.verdict.value,
                "threat_level": result.threat_level.value, "message": result.message,
            })
            if result.is_blocked:
                return True, result.layer, events, overhead

    return False, None, events, overhead


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Auto-resume any deployed agents on startup
    try:
        resume_all_agents()
    except Exception as e:
        print(f"[WARN] Failed to resume agents: {e}")
    yield
    _cleanup_port_file()


app = FastAPI(
    title="AgentArmor Studio Sidecar",
    description="Backend sidecar for AgentArmor Studio desktop app",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=False,
    allow_methods=["*"], allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/status")
async def status():
    layers = [{"name": l.name, "enabled": True} for l in armor._pipeline]  # noqa: SLF001
    layers.append({"name": armor._output_layer.name, "enabled": True})  # noqa: SLF001
    return {"status": "healthy", "version": "0.1.0", "layers": layers, "total_layers": len(layers)}


@app.get("/events")
async def events(
    limit: int = Query(100, le=500),
    agent_id: str | None = Query(None),
    layer: str | None = Query(None),
    verdict: str | None = Query(None),
):
    """Return security events from persistent storage, with optional filters."""
    entries = studio_db.get_events(limit=limit, agent_id=agent_id, layer=layer, verdict=verdict)
    # Fall back to in-memory audit trail if nothing persisted yet
    if not entries:
        entries = armor.audit.get_audit_trail(limit=limit)
        for entry in entries:
            if "timestamp" not in entry and "_timestamp" not in entry:
                entry["timestamp"] = datetime.datetime.now(datetime.UTC).isoformat()
    return {"events": entries, "count": len(entries)}


@app.get("/events/summary")
async def events_summary():
    """Return aggregate event counts for the sidebar badge and dashboard stats."""
    return studio_db.get_events_summary()


@app.post("/scan")
async def scan(req: ScanRequest):
    event = AgentEvent(agent_id=req.agent_id, event_type="scan", action="scan.prompt", input_data=req.text)
    result = await armor.process(event)
    return {
        "verdict": result.final_verdict.value, "threat_level": result.final_threat_level.value,
        "is_safe": result.is_safe, "blocked_by": result.blocked_by,
        "processing_time_ms": round(result.total_processing_time_ms, 2),
        "layers": [{"layer": lr.layer, "verdict": lr.verdict.value, "threat_level": lr.threat_level.value, "message": lr.message} for lr in result.layer_results],
    }


@app.get("/ollama/models")
async def ollama_models():
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{OLLAMA_BASE}/api/tags")
            resp.raise_for_status()
            data = resp.json()
            return {"models": [{"name": m["name"], "size": m.get("size", 0), "modified_at": m.get("modified_at", "")} for m in data.get("models", [])]}
    except Exception:
        return {"error": "Ollama not running", "models": []}


@app.get("/tools")
async def list_tools():
    return {
        "tools": [{"name": n, "description": m["description"], "action": m["action"], "parameters": m["parameters"]} for n, m in TOOL_REGISTRY.items()],
        "count": len(TOOL_REGISTRY),
    }


@app.get("/layers")
async def layers():
    c = armor.config
    return {
        "ingestion": c.ingestion.model_dump(), "storage": c.storage.model_dump(),
        "context": c.context.model_dump(), "planning": c.planning.model_dump(),
        "execution": c.execution.model_dump(), "output": c.output.model_dump(),
        "interagent": c.interagent.model_dump(), "identity": c.identity.model_dump(),
        "audit": c.audit.model_dump(),
    }


# ---------------------------------------------------------------------------
# Settings endpoints
# ---------------------------------------------------------------------------

@app.get("/settings/api-key")
async def get_api_key():
    """Return the Studio API key (for Settings page display)."""
    return {
        "api_key": STUDIO_API_KEY,
        "key_file": str(AGENTARMOR_DIR / "studio.key"),
    }


@app.post("/settings/api-key/regenerate")
async def regenerate_api_key():
    """Generate a new Studio API key."""
    global STUDIO_API_KEY
    STUDIO_API_KEY = f"aa-sk-{secrets.token_hex(24)}"
    key_file = AGENTARMOR_DIR / "studio.key"
    key_file.write_text(STUDIO_API_KEY)
    return {"api_key": STUDIO_API_KEY, "message": "API key regenerated. Update your agent configurations."}


class ExternalAPISettings(BaseModel):
    tavily_api_key: str = ""
    e2b_api_key: str = ""


@app.get("/settings/external-apis")
async def get_external_apis():
    """Get external API key settings (keys masked)."""
    tavily = studio_db.get_setting("tavily_api_key", os.environ.get("TAVILY_API_KEY", ""))
    e2b = studio_db.get_setting("e2b_api_key", os.environ.get("E2B_API_KEY", ""))
    return {
        "tavily_api_key": (tavily[:8] + "..." + tavily[-4:]) if len(tavily) > 12 else ("set" if tavily else ""),
        "e2b_api_key": (e2b[:8] + "..." + e2b[-4:]) if len(e2b) > 12 else ("set" if e2b else ""),
        "tavily_configured": bool(tavily),
        "e2b_configured": bool(e2b),
    }


@app.post("/settings/external-apis")
async def set_external_apis(req: ExternalAPISettings):
    """Save external API keys to studio.db settings."""
    if req.tavily_api_key:
        studio_db.set_setting("tavily_api_key", req.tavily_api_key)
    if req.e2b_api_key:
        studio_db.set_setting("e2b_api_key", req.e2b_api_key)
    return {"success": True, "message": "API keys saved"}


class NetworkPolicySettings(BaseModel):
    allow_http: bool = False
    max_payload: str = "1024"

@app.get("/settings/network-policy")
async def get_network_policy():
    """Get L5 Network Policy settings."""
    allow = studio_db.get_setting("network_allow_http", "False") == "True"
    payload = studio_db.get_setting("network_max_payload", "1024")
    return {"allow_http": allow, "max_payload": payload}

@app.post("/settings/network-policy")
async def set_network_policy(req: NetworkPolicySettings):
    """Save L5 Network Policy settings."""
    studio_db.set_setting("network_allow_http", str(req.allow_http))
    studio_db.set_setting("network_max_payload", req.max_payload)
    return {"success": True, "message": "Network policy saved"}

# ---------------------------------------------------------------------------
# Conversation History endpoints
# ---------------------------------------------------------------------------

class ConversationCreateRequest(BaseModel):
    agent_id: str = "studio"
    title: str = ""


class MessageAppendRequest(BaseModel):
    role: str
    content: str
    tool_calls: list[dict[str, Any]] = []
    security_events: list[dict[str, Any]] = []


@app.get("/conversations")
async def list_conversations(agent_id: str | None = Query(None), limit: int = Query(50)):
    """List conversations, optionally filtered by agent."""
    convos = studio_db.get_conversations(agent_id=agent_id, limit=limit)
    return {"conversations": convos, "count": len(convos)}


@app.post("/conversations")
async def create_conversation(req: ConversationCreateRequest):
    """Start a new conversation."""
    cid = studio_db.create_conversation(agent_id=req.agent_id, title=req.title)
    return {"conversation_id": cid, "agent_id": req.agent_id}


@app.get("/conversations/{conversation_id}")
async def get_conversation(conversation_id: str):
    """Get all messages in a conversation."""
    messages = studio_db.get_messages(conversation_id)
    return {"conversation_id": conversation_id, "messages": messages, "count": len(messages)}


@app.post("/conversations/{conversation_id}/messages")
async def append_message(conversation_id: str, req: MessageAppendRequest):
    """Append a message to a conversation."""
    msg_id = studio_db.append_message(
        conversation_id=conversation_id,
        role=req.role,
        content=req.content,
        tool_calls=req.tool_calls,
        security_events=req.security_events,
    )
    return {"success": True, "message_id": msg_id}


@app.delete("/conversations/{conversation_id}")
async def delete_conversation(conversation_id: str):
    """Delete a conversation and all its messages."""
    studio_db.delete_conversation(conversation_id)
    return {"success": True}


# ---------------------------------------------------------------------------
# Agent Registry endpoints
# ---------------------------------------------------------------------------

@app.get("/agents")
async def list_agents():
    """List all registered agents (read-only, no auth needed)."""
    agents = studio_db.get_agents()
    return {"agents": agents, "count": len(agents)}


@app.post("/agents/register")
async def register_agent(
    req: AgentRegisterRequest,
    authorization: str | None = Header(None),
):
    """Register an external agent. Requires Studio API key."""
    _validate_api_key(authorization)

    # Register with AgentArmor L8 Identity layer too
    try:
        armor.l8_identity.register_agent(
            agent_id=req.agent_id,
            agent_type=req.agent_type,
            permissions=set(req.permissions),
        )
    except Exception:
        pass  # May already be registered

    result = studio_db.register_agent(
        agent_id=req.agent_id,
        framework=req.framework,
        agent_type=req.agent_type,
        permissions=req.permissions,
    )
    # Ensure workspace exists for the agent
    get_workspace(req.agent_id)

    return {
        "success": True,
        "agent_id": req.agent_id,
        "message": f"Agent '{req.agent_id}' registered successfully",
    }


@app.post("/agents/{agent_id}/heartbeat")
async def agent_heartbeat(
    agent_id: str,
    authorization: str | None = Header(None),
):
    """Update agent heartbeat timestamp. Requires Studio API key."""
    _validate_api_key(authorization)
    agents = studio_db.get_agents()
    if not any(a["agent_id"] == agent_id for a in agents):
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not registered")
    studio_db.update_heartbeat(agent_id)
    return {"success": True}


@app.post("/agents/{agent_id}/event")
async def agent_event(
    agent_id: str,
    req: AgentEventRequest,
    authorization: str | None = Header(None),
):
    """Receive a security event from an external agent. Requires Studio API key."""
    _validate_api_key(authorization)

    agents = studio_db.get_agents()
    if not any(a["agent_id"] == agent_id for a in agents):
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not registered")

    blocked = req.verdict == "deny"
    studio_db.update_heartbeat(agent_id)
    studio_db.increment_event_count(agent_id, blocked=blocked)

    # Log to audit trail + persist to event store
    ext_event = AgentEvent(
        agent_id=agent_id,
        event_type=req.event_type,
        action=req.action,
        params=req.params,
    )
    armor.audit.log_event(ext_event)
    studio_db.store_event({
        "agent_id": agent_id, "event_type": req.event_type,
        "action": req.action, "verdict": req.verdict,
        "_timestamp": time.time(),
    })

    return {"success": True, "event_logged": True}


@app.delete("/agents/{agent_id}")
async def unregister_agent(
    agent_id: str,
    authorization: str | None = Header(None),
):
    """Unregister an external agent. Requires Studio API key."""
    _validate_api_key(authorization)
    if agent_id == "studio":
        raise HTTPException(status_code=400, detail="Cannot unregister the built-in studio agent")
    agents = studio_db.get_agents()
    if not any(a["agent_id"] == agent_id for a in agents):
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not registered")
    studio_db.unregister_agent(agent_id)
    return {"success": True, "message": f"Agent '{agent_id}' unregistered"}


class AgentToolRequest(BaseModel):
    tool: str
    args: dict[str, Any] = {}
    agent_id: str = "unknown"


@app.post("/agent/tool")
async def agent_tool_proxy(
    req: AgentToolRequest,
    authorization: str | None = Header(None),
):
    """Proxy tool execution for generated agents.

    Generated LangGraph agents call this endpoint to execute tools in the
    Studio sandbox (Tavily search, per-agent SQLite, sandboxed file I/O, E2B code).
    Each call is authenticated with the Studio API key and the result is logged.
    """
    _validate_api_key(authorization)

    tool_meta = TOOL_REGISTRY.get(req.tool)
    if not tool_meta:
        raise HTTPException(status_code=404, detail=f"Unknown tool: {req.tool}")

    # For per-agent workspace tools, inject the agent_id if the fn supports it
    fn = tool_meta["fn"]
    import inspect as _inspect
    sig = _inspect.signature(fn)
    call_args = dict(req.args)
    if "agent_id" in sig.parameters:
        call_args["agent_id"] = req.agent_id

    try:
        result = fn(**call_args)
    except Exception as e:
        result = f"Tool error: {e}"

    # Persist the tool event (non-blocking)
    studio_db.store_event({
        "agent_id": req.agent_id,
        "event_type": "tool_call",
        "action": f"tool.{req.tool}",
        "verdict": "allow",
        "layer": "L5",
        "_timestamp": time.time(),
        "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
    })
    studio_db.update_heartbeat(req.agent_id)

    return {"result": result, "tool": req.tool}


# ---------------------------------------------------------------------------
# Agent Runner — tool-calling agent loop
# ---------------------------------------------------------------------------

@app.post("/agent/run")
async def agent_run(req: OllamaAgentRequest):
    """Run an AgentArmor-wrapped Ollama agent with tool calling.

    Pipeline:
      1. L1 scan user message
      2. Call Ollama with tools
      3. Loop: while model returns tool_calls:
           L4 (risk) → L5 (sandbox) → L8 (identity) → execute → L6 (PII)
           Feed result back → Ollama continues
      4. L6 scan final response
      5. Return response + all events + tool call log
    """
    t0 = time.perf_counter()
    all_events: list[dict[str, Any]] = []
    tool_calls_log: list[dict[str, Any]] = []
    sec_ms = 0.0
    enabled = set(req.layers_enabled)

    # ── Step 1: L1 scan ──
    scan_event = AgentEvent(agent_id="studio", event_type="scan", action="ingestion.scan", input_data=req.user_message)
    armor.audit.log_event(scan_event)

    t = time.perf_counter()
    l1 = await _run_layer(1, scan_event, enabled)
    sec_ms += (time.perf_counter() - t) * 1000
    if l1:
        event_entry = {
            "layer": l1.layer, "verdict": l1.verdict.value,
            "threat_level": l1.threat_level.value, "message": l1.message,
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
        }
        all_events.append(event_entry)
        studio_db.store_event({**event_entry, "agent_id": "studio", "_timestamp": time.time()})
        if l1.is_blocked:
            return {"response": "", "blocked": True, "blocked_by": l1.layer, "events": all_events, "tool_calls": [],
                    "latency_ms": round((time.perf_counter() - t0) * 1000), "security_overhead_ms": round(sec_ms)}

    # ── Step 2: Ollama tool-calling loop ──
    # L3 Context Layer: Build hardened system prompt with tier instruction,
    # multi-canary injection, and goal lock anchor.
    l3 = _get_l3_layer()
    conversation_id = f"studio-{id(req)}"  # ephemeral per-request if no persistent conv
    turn_number = _next_turn(conversation_id)

    hardened_system = l3.build_secure_system_prompt(
        base_system_prompt=req.system_prompt,
        conversation_id=conversation_id,
    )
    messages = [{"role": "system", "content": hardened_system}]
    messages.extend(req.conversation_history)
    messages.append({"role": "user", "content": req.user_message})

    # Collect any L3 events from system prompt construction (e.g. template strip)
    l3_build_events = get_and_clear_l3_events()
    for evt in l3_build_events:
        evt["timestamp"] = datetime.datetime.now(datetime.UTC).isoformat()
        all_events.append(evt)
        studio_db.store_event({**evt, "agent_id": "studio", "_timestamp": time.time()})

    final_text = ""
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            for iteration in range(10):  # max 10 tool-call rounds
                resp = await client.post(f"{OLLAMA_BASE}/api/chat", json={
                    "model": req.model, "messages": messages, "tools": OLLAMA_TOOLS, "stream": False,
                })
                resp.raise_for_status()
                msg = resp.json().get("message", {})
                tool_calls = msg.get("tool_calls", [])

                if not tool_calls:
                    final_text = msg.get("content", "")
                    break

                messages.append(msg)

                for tc in tool_calls:
                    fn = tc.get("function", {})
                    fn_name = fn.get("name", "unknown")
                    fn_args = fn.get("arguments", {})
                    tc_log: dict[str, Any] = {
                        "tool": fn_name, "args": fn_args,
                        "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
                    }

                    # Security check
                    blocked, blocked_by, sec_events, overhead = await _security_check_tool_call(fn_name, fn_args, enabled, session_id=conversation_id)
                    sec_ms += overhead
                    all_events.extend(sec_events)
                    tc_log["security_events"] = sec_events

                    if blocked:
                        tc_log["blocked"] = True
                        tc_log["blocked_by"] = blocked_by
                        tc_log["result"] = f"BLOCKED by {blocked_by}"
                        tool_calls_log.append(tc_log)
                        messages.append({"role": "tool", "content": f"Tool call BLOCKED by security layer {blocked_by}. Action denied."})
                        continue

                    # Execute tool through L5 gate
                    tool_meta = TOOL_REGISTRY.get(fn_name)
                    if tool_meta:
                        l5 = _get_l5_layer()
                        outbound_url = str(fn_args.get("url", fn_args.get("query", "")))
                        outbound_payload = str(fn_args.get("body", fn_args.get("data", "")))
                        t_l5 = time.perf_counter()
                        l5_result, l5_event = await l5.execute(
                            tool_name=fn_name, tool_args=fn_args,
                            tool_func=tool_meta["fn"], session_id=conversation_id,
                            outbound_url=outbound_url, outbound_payload=outbound_payload,
                        )
                        sec_ms += (time.perf_counter() - t_l5) * 1000

                        # Emit L5 event
                        l5_event["timestamp"] = datetime.datetime.now(datetime.UTC).isoformat()
                        all_events.append(l5_event)
                        studio_db.store_event({**l5_event, "agent_id": "studio", "_timestamp": time.time()})

                        if l5_event.get("verdict") == "block":
                            tc_log["blocked"] = True
                            tc_log["blocked_by"] = "L5_Execution"
                            tc_log["result"] = l5_result.get("error", "BLOCKED by L5")
                            tool_calls_log.append(tc_log)
                            messages.append({"role": "tool", "content": tc_log["result"]})
                            continue

                        result_text = l5_result if isinstance(l5_result, str) else str(l5_result)
                    else:
                        result_text = f"Unknown tool: {fn_name}"

                    # Sub-task E: L1 scan tool output
                    if 1 in enabled:
                        t_l1_out = time.perf_counter()
                        marked_content, scan_res = await l1_tools.scan_tool_output(fn_name, result_text, "studio")
                        sec_ms += (time.perf_counter() - t_l1_out) * 1000
                        l1_evt = {
                            "layer": "L1-Indirect", "verdict": scan_res["verdict"],
                            "threat_level": scan_res["threat_level"], "message": f"Scan found {len(scan_res['anomalies_found'])} anomalies",
                            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
                            "details": scan_res
                        }
                        all_events.append(l1_evt)
                        studio_db.store_event({**l1_evt, "agent_id": "studio", "_timestamp": time.time()})
                        if scan_res["verdict"] == "block":
                            result_text = f"[BLOCKED by AgentArmor L1: Indirect injection detected in tool output. Source: {fn_name}]"
                        else:
                            result_text = marked_content

                    # L6 scan tool output
                    if 6 in enabled:
                        t = time.perf_counter()
                        l6 = _get_l6_layer()
                        result_text, out_result = l6.process(result_text, conversation_id)
                        sec_ms += (time.perf_counter() - t) * 1000
                        l6_entry = {
                            "layer": out_result["layer"], "verdict": out_result["verdict"],
                            "threat_level": out_result["threat_level"], "message": f"Scan generated {out_result['findings_count']} findings",
                            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
                            "details": out_result,
                        }
                        # Also generate an AgentEvent structure for the audit logger since we bypass `armor.scan_output`
                        out_evt = AgentEvent(agent_id="studio", event_type="tool_output", action="output.scan", output_data=result_text)
                        armor.audit.log_layer_result(out_evt, LayerResult(
                            layer=out_result["layer"],
                            verdict=SecurityVerdict.ALLOW if out_result["verdict"] == "allow" else SecurityVerdict.MODIFY if out_result["verdict"] == "redacted" else SecurityVerdict.DENY if out_result["verdict"] == "block" else SecurityVerdict.ESCALATE,
                            threat_level=ThreatLevel.NONE if out_result["threat_level"] == "none" else ThreatLevel.LOW if out_result["threat_level"] == "low" else ThreatLevel.MEDIUM if out_result["threat_level"] == "medium" else ThreatLevel.HIGH if out_result["threat_level"] == "high" else ThreatLevel.CRITICAL,
                            message=f"L6 findings: {out_result['findings_count']}",
                        ))
                        all_events.append(l6_entry)
                        studio_db.store_event({**l6_entry, "agent_id": "studio", "_timestamp": time.time()})

                    tc_log["blocked"] = False
                    tc_log["result"] = result_text[:500]
                    tool_calls_log.append(tc_log)
                    messages.append({"role": "tool", "content": result_text})

    except Exception as exc:
        return {"response": "", "blocked": True, "blocked_by": "ollama_error", "error": str(exc),
                "events": all_events, "tool_calls": tool_calls_log,
                "latency_ms": round((time.perf_counter() - t0) * 1000), "security_overhead_ms": round(sec_ms)}

    # ── Step 3: L3 output check (canary scan + goal drift) ──
    if 3 in enabled and final_text:
        t = time.perf_counter()
        final_text, l3_output_events = await l3.check_output(
            conversation_id=conversation_id,
            response=final_text,
            tool_calls=tool_calls_log,
            turn_number=turn_number,
            user_message=req.user_message,
        )
        sec_ms += (time.perf_counter() - t) * 1000
        for evt in l3_output_events:
            evt["timestamp"] = datetime.datetime.now(datetime.UTC).isoformat()
            all_events.append(evt)
            studio_db.store_event({**evt, "agent_id": "studio", "_timestamp": time.time()})

    # ── Step 4: L6 final response scan ──
    if 6 in enabled and final_text:
        t = time.perf_counter()
        l6 = _get_l6_layer()
        final_text, out_result = l6.process(final_text, conversation_id)
        sec_ms += (time.perf_counter() - t) * 1000
        
        l6_entry = {
            "layer": out_result["layer"], "verdict": out_result["verdict"],
            "threat_level": out_result["threat_level"], "message": f"Scan generated {out_result['findings_count']} findings",
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "details": out_result,
        }
        out_evt = AgentEvent(agent_id="studio", event_type="scan_output", action="output.scan", output_data=final_text)
        armor.audit.log_layer_result(out_evt, LayerResult(
            layer=out_result["layer"],
            verdict=SecurityVerdict.ALLOW if out_result["verdict"] == "allow" else SecurityVerdict.MODIFY if out_result["verdict"] == "redacted" else SecurityVerdict.DENY if out_result["verdict"] == "block" else SecurityVerdict.ESCALATE,
            threat_level=ThreatLevel.NONE if out_result["threat_level"] == "none" else ThreatLevel.LOW if out_result["threat_level"] == "low" else ThreatLevel.MEDIUM if out_result["threat_level"] == "medium" else ThreatLevel.HIGH if out_result["threat_level"] == "high" else ThreatLevel.CRITICAL,
            message=f"L6 findings: {out_result['findings_count']}",
        ))
        
        all_events.append(l6_entry)
        studio_db.store_event({**l6_entry, "agent_id": "studio", "_timestamp": time.time()})
        
        # Defense-in-depth: if L6 catches canary tokens, it will return verdict="block".
        if out_result["verdict"] == "block":
            final_text = "[AgentArmor L6 BLOCKED] This response was blocked because it triggered a critical output security rule. The agent may have been manipulated."

    return {
        "response": final_text, "blocked": False, "blocked_by": None,
        "events": all_events, "tool_calls": tool_calls_log,
        "latency_ms": round((time.perf_counter() - t0) * 1000),
    }



# ---------------------------------------------------------------------------
# Agent Runner — SSE streaming version
# ---------------------------------------------------------------------------

@app.post("/agent/run/stream")
async def agent_run_stream(req: OllamaAgentRequest):
    """Streaming version of /agent/run — emits SSE events as they fire.

    Frontend reads via fetch() with streaming body; each event is:
      data: {"type": "layer_check"|"tool_start"|"tool_result"|"final"|"error", ...}\n\n
    """
    async def generate():
        def sse(event_type: str, payload: dict) -> str:
            return f"data: {json.dumps({'type': event_type, **payload})}\n\n"

        t0 = time.perf_counter()
        all_events: list[dict[str, Any]] = []
        tool_calls_log: list[dict[str, Any]] = []
        sec_ms = 0.0
        enabled = set(req.layers_enabled)
        now_iso = lambda: datetime.datetime.now(datetime.UTC).isoformat()

        # ── L1 scan ──
        scan_event = AgentEvent(agent_id="studio", event_type="scan", action="ingestion.scan", input_data=req.user_message)
        armor.audit.log_event(scan_event)
        yield sse("layer_start", {"layer": "L1_ingestion", "message": "Scanning input for prompt injection", "timestamp": now_iso()})
        t = time.perf_counter()
        l1 = await _run_layer(1, scan_event, enabled)
        sec_ms += (time.perf_counter() - t) * 1000
        if l1:
            entry = {
                "layer": l1.layer, "verdict": l1.verdict.value,
                "threat_level": l1.threat_level.value, "message": l1.message,
                "details": l1.details, "latency_ms": round((time.perf_counter() - t) * 1000),
                "timestamp": now_iso(),
            }
            all_events.append(entry)
            studio_db.store_event({**entry, "agent_id": "studio", "_timestamp": time.time()})
            yield sse("layer_complete", entry)
            yield sse("layer_check", entry)
            if l1.is_blocked:
                yield sse("final", {"response": "", "blocked": True, "blocked_by": l1.layer,
                                    "events": all_events, "tool_calls": [], "latency_ms": round((time.perf_counter() - t0) * 1000)})
                return

        # ── Ollama tool-calling loop ──
        # L3 Context Layer: Build hardened system prompt
        l3 = _get_l3_layer()
        conversation_id = f"studio-stream-{id(req)}"
        turn_number = _next_turn(conversation_id)

        hardened_system = l3.build_secure_system_prompt(
            base_system_prompt=req.system_prompt,
            conversation_id=conversation_id,
        )
        messages = [{"role": "system", "content": hardened_system}]
        messages.extend(req.conversation_history)
        messages.append({"role": "user", "content": req.user_message})

        # Collect any L3 events from system prompt construction
        l3_build_events = get_and_clear_l3_events()
        for evt in l3_build_events:
            evt["timestamp"] = now_iso()
            all_events.append(evt)
            studio_db.store_event({**evt, "agent_id": "studio", "_timestamp": time.time()})
            yield sse("layer_check", evt)

        final_text = ""

        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                for _iteration in range(10):
                    llm_t0 = time.perf_counter()
                    yield sse("llm_request_start", {
                        "model": req.model, "iteration": _iteration,
                        "timestamp": now_iso(),
                    })
                    resp = await client.post(f"{OLLAMA_BASE}/api/chat", json={
                        "model": req.model, "messages": messages, "tools": OLLAMA_TOOLS, "stream": False,
                    })
                    resp.raise_for_status()
                    msg = resp.json().get("message", {})
                    tool_calls = msg.get("tool_calls", [])
                    yield sse("llm_response", {
                        "model": req.model, "iteration": _iteration,
                        "tool_calls_count": len(tool_calls),
                        "content_len": len(msg.get("content", "")),
                        "latency_ms": round((time.perf_counter() - llm_t0) * 1000),
                        "timestamp": now_iso(),
                    })

                    if not tool_calls:
                        final_text = msg.get("content", "")
                        break

                    messages.append(msg)

                    for tc in tool_calls:
                        fn = tc.get("function", {})
                        fn_name = fn.get("name", "unknown")
                        fn_args = fn.get("arguments", {})

                        # Emit tool start immediately
                        yield sse("tool_start", {"tool": fn_name, "args": fn_args, "timestamp": now_iso()})

                        # Security check
                        blocked, blocked_by, sec_events, overhead = await _security_check_tool_call(fn_name, fn_args, enabled, session_id=conversation_id)
                        sec_ms += overhead
                        all_events.extend(sec_events)
                        for se in sec_events:
                            yield sse("layer_check", se)

                        if blocked:
                            yield sse("tool_result", {"tool": fn_name, "blocked": True, "blocked_by": blocked_by,
                                                       "result": f"BLOCKED by {blocked_by}", "timestamp": now_iso()})
                            tool_calls_log.append({"tool": fn_name, "args": fn_args, "blocked": True,
                                                   "blocked_by": blocked_by, "result": f"BLOCKED by {blocked_by}"})
                            messages.append({"role": "tool", "content": f"Tool call BLOCKED by {blocked_by}."})
                            continue

                        # Execute tool through L5 gate
                        tool_meta = TOOL_REGISTRY.get(fn_name)
                        if tool_meta:
                            l5 = _get_l5_layer(req.agent_id)
                            outbound_url = str(fn_args.get("url", fn_args.get("query", "")))
                            outbound_payload = str(fn_args.get("body", fn_args.get("data", "")))
                            t_l5 = time.perf_counter()
                            l5_result, l5_event = await l5.execute(
                                tool_name=fn_name, tool_args=fn_args,
                                tool_func=tool_meta["fn"], session_id=conversation_id,
                                outbound_url=outbound_url, outbound_payload=outbound_payload,
                            )
                            sec_ms += (time.perf_counter() - t_l5) * 1000

                            # Emit L5 event
                            l5_event["timestamp"] = now_iso()
                            all_events.append(l5_event)
                            studio_db.store_event({**l5_event, "agent_id": "studio", "_timestamp": time.time()})
                            yield sse("layer_check", l5_event)

                            if l5_event.get("verdict") == "block":
                                yield sse("tool_result", {"tool": fn_name, "blocked": True, "blocked_by": "L5_Execution",
                                                           "result": l5_result.get("error", "BLOCKED by L5"), "timestamp": now_iso()})
                                tool_calls_log.append({"tool": fn_name, "args": fn_args, "blocked": True,
                                                       "blocked_by": "L5_Execution", "result": l5_result.get("error", "BLOCKED by L5")})
                                messages.append({"role": "tool", "content": l5_result.get("error", "BLOCKED by L5")})
                                continue

                            result_text = l5_result if isinstance(l5_result, str) else str(l5_result)
                        else:
                            result_text = f"Unknown tool: {fn_name}"

                        # Sub-task E: L1 scan tool output
                        if 1 in enabled:
                            t_l1_out = time.perf_counter()
                            marked_content, scan_res = await l1_tools.scan_tool_output(fn_name, result_text, "studio")
                            sec_ms += (time.perf_counter() - t_l1_out) * 1000
                            l1_evt = {
                                "layer": "L1-Indirect", "verdict": scan_res["verdict"],
                                "threat_level": scan_res["threat_level"], "message": f"Scan found {len(scan_res['anomalies_found'])} anomalies",
                                "timestamp": now_iso(), "details": scan_res
                            }
                            all_events.append(l1_evt)
                            studio_db.store_event({**l1_evt, "agent_id": "studio", "_timestamp": time.time()})
                            yield sse("layer_check", l1_evt)

                            if scan_res["verdict"] == "block":
                                result_text = f"[BLOCKED by AgentArmor L1: Indirect injection detected in tool output. Source: {fn_name}]"
                            else:
                                result_text = marked_content

                        # L6 scan tool output
                        if 6 in enabled:
                            t_l6 = time.perf_counter()
                            l6 = _get_l6_layer()
                            result_text, out_result = l6.process(result_text, conversation_id)
                            sec_ms += (time.perf_counter() - t_l6) * 1000
                            l6e = {
                                "layer": out_result["layer"], "verdict": out_result["verdict"],
                                "threat_level": out_result["threat_level"], "message": f"Scan generated {out_result['findings_count']} findings", 
                                "timestamp": now_iso(), "details": out_result
                            }
                            all_events.append(l6e)
                            studio_db.store_event({**l6e, "agent_id": "studio", "_timestamp": time.time()})
                            yield sse("layer_check", l6e)

                        yield sse("tool_result", {"tool": fn_name, "blocked": False,
                                                   "result": str(result_text)[:500], "timestamp": now_iso()})
                        tool_calls_log.append({"tool": fn_name, "args": fn_args, "blocked": False, "result": str(result_text)[:500]})
                        messages.append({"role": "tool", "content": result_text})

        except Exception as exc:
            yield sse("error", {"message": str(exc), "latency_ms": round((time.perf_counter() - t0) * 1000)})
            return

        # ── L3 output check (canary scan + goal drift) ──
        if 3 in enabled and final_text:
            t_l3o = time.perf_counter()
            final_text, l3_output_events = await l3.check_output(
                conversation_id=conversation_id,
                response=final_text,
                tool_calls=tool_calls_log,
                turn_number=turn_number,
                user_message=req.user_message,
            )
            sec_ms += (time.perf_counter() - t_l3o) * 1000
            for evt in l3_output_events:
                evt["timestamp"] = now_iso()
                all_events.append(evt)
                studio_db.store_event({**evt, "agent_id": "studio", "_timestamp": time.time()})
                yield sse("layer_check", evt)

        # ── L6 final response scan ──
        if 6 in enabled and final_text:
            yield sse("layer_start", {"layer": "L6_output", "message": "Scanning final response", "timestamp": now_iso()})
            t_l6f = time.perf_counter()
            l6 = _get_l6_layer()
            final_text, out_result = l6.process(final_text, conversation_id)
            sec_ms += (time.perf_counter() - t_l6f) * 1000
            l6fe = {
                "layer": out_result["layer"], "verdict": out_result["verdict"],
                "threat_level": out_result["threat_level"],
                "message": f"Scan generated {out_result['findings_count']} findings",
                "latency_ms": round((time.perf_counter() - t_l6f) * 1000),
                "timestamp": now_iso(), "details": out_result,
            }
            all_events.append(l6fe)
            studio_db.store_event({**l6fe, "agent_id": req.agent_id or "studio", "_timestamp": time.time()})
            yield sse("layer_complete", l6fe)
            yield sse("layer_check", l6fe)
            if out_result["verdict"] == "block":
                final_text = "[AgentArmor L6 BLOCKED] This response was blocked because it triggered a critical output security rule. The agent may have been manipulated."

        yield sse("final", {
            "response": final_text, "blocked": False, "blocked_by": None,
            "events": all_events, "tool_calls": tool_calls_log,
            "latency_ms": round((time.perf_counter() - t0) * 1000),
            "security_overhead_ms": round(sec_ms),
        })

    return StreamingResponse(generate(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---------------------------------------------------------------------------
# Builder endpoints
# ---------------------------------------------------------------------------

@app.post("/builder/deploy")
async def builder_deploy(req: BuilderDeployRequest):
    """Generate and spawn a new custom agent via uv run."""
    import sys
    import secrets
    from pathlib import Path

    # Import builder modules — use the same fallback as the top-level imports
    try:
        from builder.generator import generate_agent_script
        from builder.runner import deploy_agent
    except ImportError:
        from sidecar.builder.generator import generate_agent_script
        from sidecar.builder.runner import deploy_agent

    agent_id = f"{req.name.lower().replace(' ', '-')}-{secrets.token_hex(4)}"

    port_file = Path.home() / ".agentarmor" / ".sidecar_port"
    sidecar_port = int(port_file.read_text().strip()) if port_file.exists() else 8457

    script = generate_agent_script(
        agent_id=agent_id,
        name=req.name,
        system_prompt=req.system_prompt,
        provider=req.provider,
        provider_model=req.provider_model,
        provider_api_key=req.provider_api_key,
        layers=req.layers,
        tools=req.tools,
        studio_api_key=STUDIO_API_KEY,
        studio_port=sidecar_port,
    )

    # Pre-register the agent so the DB has the network policy before the agent's first heartbeat
    studio_db.register_agent(
        agent_id=agent_id,
        framework="langgraph",
        agent_type="general",
        name=req.name,
        system_prompt=req.system_prompt,
        layers_enabled=req.layers,
        tools_enabled=req.tools,
        provider=req.provider,
        provider_model=req.provider_model,
        network_policy={
            "isolation_level": req.isolation_level,
            "domain_allowlist": req.domain_allowlist,
            "blocked_domains": req.blocked_domains,
        }
    )

    success = deploy_agent(agent_id, script)

    if not success:
        raise HTTPException(status_code=500, detail="Failed to spawn agent subprocess")

    return {"success": True, "agent_id": agent_id}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AgentArmor Sidecar")
    parser.add_argument("--port", type=int, default=0, help="Port (0 = random)")
    args = parser.parse_args()

    port = args.port if args.port > 0 else _get_free_port()
    _write_port(port)
    atexit.register(_cleanup_port_file)

    if sys.platform != "win32":
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    print(f"[AgentArmor Sidecar] Starting on http://127.0.0.1:{port}")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")
