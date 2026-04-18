"""generator.py — Produces a self-contained, PEP-723 LangGraph ReAct agent script.

The generated script:
  - Uses a real LangGraph StateGraph (call_model → execute_tools loop)
  - Injects AgentArmor security at three points:
      L1 Ingestion  →  before input enters the graph
      L4/L5 layer   →  before each tool call executes
      L6 Output     →  before the final response is returned
  - Proxies all tool execution through the Studio sidecar REST API
    (so the sidecar's real Tavily / SQLite / file sandbox run)
  - Registers and heartbeats with Studio on startup
  - Runs a real stdin chat loop so the terminal shows live conversation
"""

import json


def _provider_block(provider: str, model: str, api_key: str) -> tuple[str, str, str, str]:
    """Return (dependency_line, import_line, init_line, env_line) for the chosen provider."""
    if provider == "openai":
        dep = '"langchain-openai"'
        imp = "from langchain_openai import ChatOpenAI"
        init = f'llm = ChatOpenAI(model="{model or "gpt-4o-mini"}", temperature=0)'
        env = f'os.environ["OPENAI_API_KEY"] = "{api_key}"' if api_key else ""
    elif provider == "anthropic":
        dep = '"langchain-anthropic"'
        imp = "from langchain_anthropic import ChatAnthropic"
        init = f'llm = ChatAnthropic(model="{model or "claude-3-5-sonnet-20240620"}", temperature=0)'
        env = f'os.environ["ANTHROPIC_API_KEY"] = "{api_key}"' if api_key else ""
    elif provider == "groq":
        dep = '"langchain-groq"'
        imp = "from langchain_groq import ChatGroq"
        init = f'llm = ChatGroq(model="{model or "llama-3.3-70b-versatile"}", temperature=0)'
        env = f'os.environ["GROQ_API_KEY"] = "{api_key}"' if api_key else ""
    else:  # ollama (default / local)
        dep = '"langchain-ollama"'
        imp = "from langchain_ollama import ChatOllama"
        init = f'llm = ChatOllama(model="{model or "llama3.2"}", temperature=0)'
        env = ""
    return dep, imp, init, env


def generate_agent_script(
    agent_id: str,
    name: str,
    system_prompt: str,
    provider: str,
    provider_model: str,
    provider_api_key: str,
    layers: list[int],
    tools: list[str],
    studio_api_key: str,
    studio_port: int,
) -> str:
    """Generate a standalone PEP-723 LangGraph ReAct agent script.

    The script is self-bootstrapping: `uv run agent.py` will install its own
    dependencies into an ephemeral venv, register with Studio, and start
    a stdin chat loop.
    """
    provider_dep, provider_import, provider_init, env_setup = _provider_block(
        provider, provider_model, provider_api_key
    )

    # Serialise config for injection into the script
    layers_repr = repr(sorted(layers))
    tools_repr = repr(sorted(tools))
    system_prompt_escaped = system_prompt.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

    # Build the LangChain tool definitions (only for tools the user enabled)
    tool_definitions = _build_tool_definitions(tools)

    script = f'''# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "agentarmor-core",
#   "requests",
#   "langchain-core",
#   {provider_dep},
#   "langgraph>=0.2",
# ]
# ///
"""
Agent: {name}
ID:    {agent_id}
Built by AgentArmor Studio — https://github.com/Agastya910/agentarmor
"""

import os, sys, json, asyncio, time
from typing import Annotated, TypedDict
import requests

# Force UTF-8 on Windows console
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

{provider_import}
from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage, AIMessage
from langchain_core.tools import tool
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from agentarmor import AgentArmor, ArmorConfig
from agentarmor.core.config import (
    ArmorConfig, IngestionConfig, StorageConfig, ContextConfig,
    PlanningConfig, ExecutionConfig, OutputConfig, InterAgentConfig, IdentityConfig
)
from agentarmor.core.types import AgentEvent

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
{f"{env_setup}" if env_setup else ""}

# ---------------------------------------------------------------------------
# Studio Discovery
# ---------------------------------------------------------------------------
def _discover_studio_url():
    import tempfile
    from pathlib import Path
    port_file = Path(tempfile.gettempdir()) / "agentarmor_sidecar.port"
    if port_file.exists():
        try:
            port = int(port_file.read_text().strip())
            return f"http://127.0.0.1:{{port}}"
        except Exception:
            pass
    return "http://127.0.0.1:8457" # Failover to default

STUDIO_URL = _discover_studio_url()
STUDIO_API_KEY = "{studio_api_key}"
AGENT_ID = "{agent_id}"
AGENT_NAME = "{name}"
LAYERS_ENABLED = set({layers_repr})
TOOLS_ENABLED = {tools_repr}

# Build AgentArmor config from the layers the user selected
armor = AgentArmor(config=ArmorConfig(
    ingestion=IngestionConfig(enabled=(1 in LAYERS_ENABLED)),
    storage=StorageConfig(enabled=(2 in LAYERS_ENABLED)),
    context=ContextConfig(enabled=(3 in LAYERS_ENABLED)),
    planning=PlanningConfig(enabled=(4 in LAYERS_ENABLED)),
    execution=ExecutionConfig(enabled=(5 in LAYERS_ENABLED)),
    output=OutputConfig(enabled=(6 in LAYERS_ENABLED)),
    interagent=InterAgentConfig(enabled=(7 in LAYERS_ENABLED)),
    identity=IdentityConfig(enabled=(8 in LAYERS_ENABLED)),
))

# ---------------------------------------------------------------------------
# LLM setup
# ---------------------------------------------------------------------------
{provider_init}

# ---------------------------------------------------------------------------
# Tool definitions — proxied through Studio sidecar REST API
# ---------------------------------------------------------------------------

def _studio_tool(tool_name: str, **kwargs) -> str:
    """Call the Studio sidecar to execute a sandboxed tool."""
    try:
        resp = requests.post(
            f"{{STUDIO_URL}}/agent/tool",
            json={{"tool": tool_name, "args": kwargs, "agent_id": AGENT_ID}},
            headers={{"Authorization": f"Bearer {{STUDIO_API_KEY}}"}},
            timeout=30,
        )
        if resp.ok:
            return resp.json().get("result", "")
        return f"Tool error: {{resp.status_code}} {{resp.text[:200]}}"
    except Exception as e:
        return f"Tool error: {{e}}"

{tool_definitions}

# Bind tools to LLM
_all_tools = [t for name, t in [
{_build_tool_list(tools)}
] if name in TOOLS_ENABLED]

llm_with_tools = llm.bind_tools(_all_tools) if _all_tools else llm

# ---------------------------------------------------------------------------
# LangGraph ReAct StateGraph
# ---------------------------------------------------------------------------

class AgentState(TypedDict):
    messages: Annotated[list, add_messages]
    blocked: bool
    blocked_by: str | None

def _report_event(action: str, verdict: str, message: str = ""):
    """Non-blocking event report to Studio."""
    try:
        requests.post(
            f"{{STUDIO_URL}}/agents/{{AGENT_ID}}/event",
            json={{"action": action, "verdict": verdict, "message": message}},
            headers={{"Authorization": f"Bearer {{STUDIO_API_KEY}}"}},
            timeout=2,
        )
    except Exception:
        pass

async def call_model(state: AgentState) -> dict:
    """LangGraph node: call the LLM with the current message history."""
    messages = state["messages"]
    response = await llm_with_tools.ainvoke(messages)
    return {{"messages": [response], "blocked": False, "blocked_by": None}}

async def execute_tools(state: AgentState) -> dict:
    """LangGraph node: run all tool calls from the last AI message."""
    last_msg = state["messages"][-1]
    results = []
    for tc in last_msg.tool_calls:
        tool_name = tc["name"]
        tool_args = tc["args"]

        # L4/L5 security check via armor
        check_event = AgentEvent(
            agent_id=AGENT_ID,
            event_type="tool_call",
            action=f"tool.{{tool_name}}",
            input_data=json.dumps(tool_args),
        )
        result = await armor.process(check_event)
        if result.is_blocked:
            _report_event(f"tool.{{tool_name}}", "deny", f"Blocked by {{result.blocked_by}}")
            print(f"  [BLOCKED] {{tool_name}} blocked by {{result.blocked_by}}")
            results.append(ToolMessage(
                content=f"Tool call blocked by AgentArmor layer {{result.blocked_by}}.",
                tool_call_id=tc["id"],
            ))
            continue

        # Execute via Studio sidecar proxy
        tool_result = _studio_tool(tool_name, **tool_args)
        _report_event(f"tool.{{tool_name}}", "allow", str(tool_result)[:120])
        _args_str = str(tool_args)[:80]
        print(f"  [TOOL] {{tool_name}}({{_args_str}})")
        results.append(ToolMessage(content=str(tool_result), tool_call_id=tc["id"]))

    return {{"messages": results}}

def should_continue(state: AgentState) -> str:
    """Router: continue to tools if the LLM requested tool calls."""
    last = state["messages"][-1]
    if hasattr(last, "tool_calls") and last.tool_calls:
        return "execute_tools"
    return END

# Build the graph
builder = StateGraph(AgentState)
builder.add_node("call_model", call_model)
builder.add_node("execute_tools", execute_tools)
builder.set_entry_point("call_model")
builder.add_conditional_edges("call_model", should_continue)
builder.add_edge("execute_tools", "call_model")
graph = builder.compile()

# ---------------------------------------------------------------------------
# Studio registration & heartbeat
# ---------------------------------------------------------------------------

def _register():
    try:
        resp = requests.post(
            f"{{STUDIO_URL}}/agents/register",
            json={{"agent_id": AGENT_ID, "framework": "langgraph", "agent_type": "general"}},
            headers={{"Authorization": f"Bearer {{STUDIO_API_KEY}}"}},
            timeout=5,
        )
        if resp.ok:
            print(f"[OK] {{AGENT_NAME}} registered with Studio ({{AGENT_ID}})")
        else:
            print(f"[WARN] Registration: {{resp.status_code}}")
    except Exception as e:
        print(f"[WARN] Registration failed: {{e}}")

async def _heartbeat_loop():
    while True:
        try:
            requests.post(
                f"{{STUDIO_URL}}/agents/{{AGENT_ID}}/heartbeat",
                headers={{"Authorization": f"Bearer {{STUDIO_API_KEY}}"}},
                timeout=2,
            )
        except Exception:
            pass
        await asyncio.sleep(5)

# ---------------------------------------------------------------------------
# Chat conversation loop
# ---------------------------------------------------------------------------

async def chat_loop():
    _register()
    asyncio.create_task(_heartbeat_loop())

    system_prompt = "{system_prompt_escaped}"
    conversation: list = [SystemMessage(content=system_prompt)]

    print(f"\\n[READY] {{AGENT_NAME}} is running. Type a message and press Enter.")
    print(f"[INFO]  Layers enabled: {{sorted(LAYERS_ENABLED)}}")
    print(f"[INFO]  Tools enabled:  {{TOOLS_ENABLED}}")
    print("-" * 60)

    while True:
        # Read input
        try:
            user_input = await asyncio.get_event_loop().run_in_executor(
                None, lambda: input("\\nYou: ")
            )
        except (EOFError, KeyboardInterrupt):
            print("\\n[SHUTDOWN] Agent stopping.")
            break

        if not user_input.strip():
            continue

        # L1 ingestion scan
        scan_evt = AgentEvent(
            agent_id=AGENT_ID,
            event_type="scan",
            action="ingestion.scan",
            input_data=user_input,
        )
        l1 = await armor.process(scan_evt)

        if l1.is_blocked:
            _report_event("ingestion.scan", "deny", l1.blocked_by or "")
            print(f"\\n[L1 BLOCKED] Input rejected: {{l1.blocked_by}}")
            print(f"[SECURITY] {{l1.final_verdict.value.upper()}} — {{l1.total_processing_time_ms:.0f}}ms overhead")
            continue

        _report_event("ingestion.scan", "allow", "")
        print(f"[L1 OK] Input passed in {{l1.total_processing_time_ms:.0f}}ms")

        # Run the LangGraph agent
        conversation.append(HumanMessage(content=user_input))
        t0 = time.perf_counter()

        state = await graph.ainvoke({{"messages": conversation}})
        elapsed = round((time.perf_counter() - t0) * 1000)

        # Extract final AI message
        final_msg = next(
            (m for m in reversed(state["messages"]) if isinstance(m, AIMessage)),
            None,
        )
        response_text = final_msg.content if final_msg else "(no response)"

        # L6 output scan
        if 6 in LAYERS_ENABLED and response_text:
            out_evt = AgentEvent(
                agent_id=AGENT_ID,
                event_type="scan_output",
                action="output.scan",
                output_data=response_text,
            )
            l6 = await armor.scan_output(out_evt)
            _report_event("output.scan", l6.verdict.value, "")
            if l6.modified_data:
                response_text = l6.modified_data
            print(f"[L6 {{l6.verdict.value.upper()}}] Output scanned in {{l6.total_processing_time_ms:.0f}}ms")

        # Update conversation history with full graph state
        conversation = list(state["messages"])

        print(f"\\n{{AGENT_NAME}}: {{response_text}}")
        print(f"[{{elapsed}}ms total]")

if __name__ == "__main__":
    try:
        asyncio.run(chat_loop())
    except KeyboardInterrupt:
        print("\\nAgent shutting down.")
'''

    return script


# ---------------------------------------------------------------------------
# Tool generation helpers
# ---------------------------------------------------------------------------

def _build_tool_definitions(tools: list[str]) -> str:
    """Return @tool decorated function definitions for each enabled tool."""
    blocks = []

    if "web_search" in tools:
        blocks.append('''\
@tool
def web_search(query: str) -> str:
    """Search the internet for real-time information about a topic."""
    return _studio_tool("web_search", query=query)
''')

    if "db_query" in tools:
        blocks.append('''\
@tool
def db_query(sql: str) -> str:
    """Execute a SQL query on this agent\'s private database. Returns JSON rows or a status message."""
    return _studio_tool("db_query", sql=sql)
''')

    if "file_read" in tools:
        blocks.append('''\
@tool
def file_read(path: str) -> str:
    """Read a file from this agent\'s sandboxed workspace directory."""
    return _studio_tool("file_read", path=path)
''')

    if "file_write" in tools:
        blocks.append('''\
@tool
def file_write(path: str, content: str) -> str:
    """Write content to a file in this agent\'s sandboxed workspace directory."""
    return _studio_tool("file_write", path=path, content=content)
''')

    if "run_code" in tools:
        blocks.append('''\
@tool
def run_code(code: str, language: str = "python") -> str:
    """Execute code in a secure E2B sandbox and return stdout/stderr."""
    return _studio_tool("run_code", code=code, language=language)
''')

    if "api_call" in tools:
        blocks.append('''\
@tool
def api_call(url: str, method: str = "GET", body: str = "") -> str:
    """Make an HTTP API call to an external service."""
    return _studio_tool("api_call", url=url, method=method, body=body)
''')

    if "web_fetch" in tools:
        blocks.append('''\
@tool
def web_fetch(url: str) -> str:
    """Fetch and return the text content of a webpage."""
    return _studio_tool("web_fetch", url=url)
''')

    return "\n".join(blocks)


def _build_tool_list(tools: list[str]) -> str:
    """Return comma-separated (name, fn) tuples for the tool registry list."""
    known = ["web_search", "db_query", "file_read", "file_write", "run_code", "api_call", "web_fetch"]
    lines = []
    for t in known:
        if t in tools:
            lines.append(f'    ("{t}", {t}),')
    return "\n".join(lines) if lines else '    # No tools selected'
