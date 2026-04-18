/**
 * Generates a Python integration snippet based on the selected framework
 * and enabled security layers.
 * 
 * Returns separate pieces: agentarmor.yaml, pip install command, and python code.
 */

export type Framework =
  | "langchain"
  | "openai-agents"
  | "mcp-server"
  | "custom-python"
  | "fastapi-proxy";

export interface IntegrationParts {
  yaml: { filename: string; code: string };
  bash: { command: string };
  python: { filename: string; code: string };
}

const LAYER_NAMES: Record<number, string> = {
  1: "ingestion",
  2: "storage",
  3: "context",
  4: "planning",
  5: "execution",
  6: "output",
  7: "interagent",
  8: "identity",
};

function layerConfig(enabledLayers: number[]): string {
  const lines = Object.entries(LAYER_NAMES).map(([id, name]) => {
    const enabled = enabledLayers.includes(Number(id));
    return `    ${name}:\n      enabled: ${enabled}`;
  });
  return lines.join("\n");
}

function generateYaml(enabledLayers: number[]): string {
  return `version: "1.0"
agent_type: general
risk_level: medium
${layerConfig(enabledLayers)}`;
}

/** Shared block that registers the agent with the Studio sidecar */
function studioRegistration(framework: string, agentId: string): string {
  return `
# ── Register with AgentArmor Studio ────────────────────────────
# This connects your agent to the Studio dashboard so you can
# monitor it in real time. Get your API key from Studio > Settings.

import requests

STUDIO_URL = "http://localhost:8457"  # AgentArmor Studio sidecar
STUDIO_API_KEY = "YOUR_STUDIO_API_KEY"  # Paste from Studio > Settings

def register_with_studio():
    \"\"\"Register this agent with AgentArmor Studio.\"\"\"
    try:
        resp = requests.post(
            f"{STUDIO_URL}/agents/register",
            json={
                "agent_id": "${agentId}",
                "framework": "${framework}",
                "agent_type": "general",
            },
            headers={"Authorization": f"Bearer {STUDIO_API_KEY}"},
            timeout=5,
        )
        if resp.ok:
            print("✅ Registered with AgentArmor Studio")
        else:
            print(f"⚠️  Studio registration failed: {resp.text}")
    except requests.ConnectionError:
        print("ℹ️  Studio not running — agent will work without it")

def report_event(action: str, verdict: str = "allow", message: str = ""):
    \"\"\"Report a security event to AgentArmor Studio.\"\"\"
    try:
        requests.post(
            f"{STUDIO_URL}/agents/${agentId}/event",
            json={"action": action, "verdict": verdict, "message": message},
            headers={"Authorization": f"Bearer {STUDIO_API_KEY}"},
            timeout=2,
        )
    except Exception:
        pass  # Non-critical — don't break the agent

# Call this when your agent starts
register_with_studio()`;
}

// ---------------------------------------------------------------------------
// Framework-specific snippets
// ---------------------------------------------------------------------------

function langchainSnippet(yaml: string): IntegrationParts {
  const code = `from agentarmor import AgentArmor, ArmorConfig
from langchain.callbacks.base import BaseCallbackHandler
from langchain_openai import ChatOpenAI

# Load config
config = ArmorConfig.from_yaml("agentarmor.yaml")
armor = AgentArmor(config=config)

class AgentArmorCallbackHandler(BaseCallbackHandler):
    """LangChain callback that scans all LLM inputs/outputs."""

    async def on_llm_start(self, serialized, prompts, **kwargs):
        for prompt in prompts:
            result = await armor.intercept(
                action="llm.input",
                input_data=prompt,
                agent_id="langchain-agent",
            )
            if not result.is_safe:
                report_event("llm.input", "deny", f"Blocked: {result.blocked_by}")
                raise ValueError(f"Blocked by {result.blocked_by}")
            report_event("llm.input", "allow")

    async def on_llm_end(self, response, **kwargs):
        for gen in response.generations:
            for g in gen:
                await armor.intercept(
                    action="llm.output",
                    output_data=g.text,
                    agent_id="langchain-agent",
                )
                report_event("llm.output", "allow")
${studioRegistration("langchain", "langchain-agent")}

# Usage example:
# llm = ChatOpenAI(model="gpt-4", callbacks=[AgentArmorCallbackHandler()])
# response = llm.invoke("Summarize our Q3 earnings report")`;

  return {
    yaml: { filename: "agentarmor.yaml", code: yaml },
    bash: { command: "pip install agentarmor-core langchain requests" },
    python: { filename: "agent.py", code },
  };
}

function openaiAgentsSnippet(yaml: string): IntegrationParts {
  const code = `import asyncio
from agentarmor import AgentArmor, ArmorConfig

config = ArmorConfig.from_yaml("agentarmor.yaml")
armor = AgentArmor(config=config)

@armor.shield(action="tool.web_search")
async def web_search(query: str) -> str:
    """Tool wrapped with AgentArmor security."""
    report_event("tool.web_search", "allow", f"query={query}")
    return f"Results for: {query}"

@armor.shield(action="tool.file_read")
async def file_read(path: str) -> str:
    """Another wrapped tool."""
    report_event("tool.file_read", "allow", f"path={path}")
    with open(path) as f:
        return f.read()
${studioRegistration("openai", "openai-agent")}

# All calls are now scanned through your enabled layers
async def main():
    result = await web_search("latest AI safety research")
    print(result)

if __name__ == "__main__":
    asyncio.run(main())`;

  return {
    yaml: { filename: "agentarmor.yaml", code: yaml },
    bash: { command: "pip install agentarmor-core openai requests" },
    python: { filename: "agent.py", code },
  };
}

function mcpServerSnippet(yaml: string): IntegrationParts {
  const code = `from agentarmor import AgentArmor, ArmorConfig
from agentarmor.integrations.mcp_server.server import create_server

config = ArmorConfig.from_yaml("agentarmor.yaml")
armor = AgentArmor(config=config)
${studioRegistration("mcp", "mcp-agent")}

# Create an MCP server with AgentArmor protection
server = create_server(armor=armor)

# Note: Add the following to your claude_desktop_config.json:
# {
#   "mcpServers": {
#     "agentarmor": {
#       "command": "python",
#       "args": ["/absolute/path/to/mcp_server.py"]
#     }
#   }
# }

if __name__ == "__main__":
    import asyncio
    asyncio.run(server.run())`;

  return {
    yaml: { filename: "agentarmor.yaml", code: yaml },
    bash: { command: "pip install agentarmor-core[mcp] requests" },
    python: { filename: "mcp_server.py", code },
  };
}

function fastapiProxySnippet(yaml: string): IntegrationParts {
  const code = `import uvicorn
from agentarmor import ArmorConfig
from agentarmor.proxy.server import create_app

config = ArmorConfig.from_yaml("agentarmor.yaml")
app = create_app(config=config)
${studioRegistration("custom", "fastapi-proxy")}

# Run the proxy
# All requests to /v1/intercept are scanned through your layers
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)

# Once running, point your agent at http://localhost:8080/v1/intercept`;

  return {
    yaml: { filename: "agentarmor.yaml", code: yaml },
    bash: { command: "pip install agentarmor-core[proxy] requests uvicorn" },
    python: { filename: "proxy_server.py", code },
  };
}

function customPythonSnippet(yaml: string): IntegrationParts {
  const code = `import asyncio
from agentarmor import AgentArmor, ArmorConfig

config = ArmorConfig.from_yaml("agentarmor.yaml")
armor = AgentArmor(config=config)
${studioRegistration("custom", "my-agent")}

async def main():
    # Example 1: Intercept a tool call manually
    result = await armor.intercept(
        action="database.query",
        params={"sql": "SELECT * FROM users"},
        agent_id="my-agent",
    )

    if result.is_safe:
        print("✅ Action allowed")
        report_event("database.query", "allow")
    else:
        print(f"❌ Blocked by: {result.blocked_by}")
        report_event("database.query", "deny", f"Blocked: {result.blocked_by}")

    # Example 2: Use the @shield decorator
    @armor.shield(action="file.write")
    async def write_file(path: str, content: str) -> str:
        with open(path, "w") as f:
            f.write(content)
        report_event("file.write", "allow", f"path={path}")
        return f"Wrote {len(content)} bytes to {path}"

    await write_file("/tmp/output.txt", "Hello, world!")

if __name__ == "__main__":
    asyncio.run(main())`;

  return {
    yaml: { filename: "agentarmor.yaml", code: yaml },
    bash: { command: "pip install agentarmor-core requests" },
    python: { filename: "agent.py", code },
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function generateSnippet(
  framework: Framework,
  enabledLayers: number[],
): IntegrationParts {
  const yaml = generateYaml(enabledLayers);
  
  switch (framework) {
    case "langchain":
      return langchainSnippet(yaml);
    case "openai-agents":
      return openaiAgentsSnippet(yaml);
    case "mcp-server":
      return mcpServerSnippet(yaml);
    case "fastapi-proxy":
      return fastapiProxySnippet(yaml);
    case "custom-python":
      return customPythonSnippet(yaml);
    default:
      return customPythonSnippet(yaml);
  }
}
