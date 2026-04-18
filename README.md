# AgentArmor Studio

A desktop application for building, deploying, and monitoring AI agents with real-time security enforcement. Built on [agentarmor-core](https://github.com/Agastya910/agentarmor).

![Windows](https://img.shields.io/badge/platform-Windows%2010%2F11-blue)
![License](https://img.shields.io/badge/license-Apache%202.0-green)
![Release](https://img.shields.io/github/v/release/Agastya910/agentarmorstudio)

## Quick Start

### Download and Install

1. Go to [Releases](https://github.com/Agastya910/agentarmorstudio/releases) and download the latest `.exe` installer
2. Run the installer (Windows 10/11, x64)
3. Install [Ollama](https://ollama.com) for local LLM support
4. Launch AgentArmor Studio

That's it. No Python, Rust, or Node.js required for end users.

### Optional: External API Keys

These are **not required** but enable additional features:

| Feature | API Key | Where to get it | Where to set it |
|---------|---------|-----------------|-----------------|
| Web Search | Tavily | [tavily.com](https://tavily.com) (free tier available) | Settings > External APIs |
| Code Execution | E2B | [e2b.dev](https://e2b.dev) (free tier available) | Settings > External APIs |
| Cloud LLMs | OpenAI / Anthropic | Their respective sites | Agent Builder > LLM Provider |

Without these keys, the app still works fully with Ollama for local LLM inference. Tools that need missing keys will tell you exactly what to configure.

## What It Does

**Agent Runner** - Chat with AI agents running behind all 8 security layers. Every message is scanned for prompt injection, every tool call is sandboxed, every response is checked for PII and credential leaks. All in real time, all visible in the UI.

**Agent Builder** - Visually assemble agents by picking an LLM provider, selecting tools (web search, file reader, command runner), toggling individual security layers, and configuring network isolation. Hit deploy and the agent starts running immediately.

**Layers** - Interactive inspector showing each of the 8 defense layers (L1 Ingestion through L8 Identity), their current status, and detailed capabilities.

**Events** - Real-time feed of every security decision: what was blocked, what passed, which layer made the call, and why.

**Dashboard** - Security score ring and layer health at a glance.

## Architecture

```
Tauri (Rust) Desktop Shell
├── React + TypeScript Frontend
│   ├── Dashboard, Builder, Runner, Layers, Events, Settings
│   └── Communicates via HTTP to localhost
└── Python Sidecar (PyInstaller bundle)
    ├── FastAPI server (auto-starts with the app)
    ├── agentarmor-core L1-L8 security pipeline
    ├── Ollama / OpenAI / Anthropic LLM integration
    └── SQLite DB (AES-256-GCM encrypted, HMAC-signed)
```

The sidecar is bundled as a standalone `.exe` inside the installer. No Python installation needed.

## Security Layers

| Layer | What It Does |
|-------|-------------|
| **L1 Ingestion** | Prompt injection detection (regex + ML classifier), Unicode normalization, CDR |
| **L2 Storage** | AES-256-GCM encryption, HMAC-SHA256 integrity MAC on all persisted data |
| **L3 Context** | Template injection stripping, canary tokens, goal-drift detection |
| **L4 Planning** | Verb-risk classification, chain escalation detection, compound risk scoring |
| **L5 Execution** | Network isolation, SSRF blocking, path traversal prevention, per-agent sandboxing |
| **L6 Output** | Credential scanning, PII redaction (Presidio), exfiltration pattern detection |
| **L7 Inter-Agent** | Replay prevention, delegation certificates, trust scoring, anomaly detection |
| **L8 Identity** | API key validation, RBAC, session binding, permission boundaries |

## Development Setup

For contributors who want to build from source:

### Prerequisites
- [Node.js](https://nodejs.org/) 18+
- [Rust](https://www.rust-lang.org/) (for Tauri)
- [Python](https://www.python.org/) 3.11+ with [uv](https://docs.astral.sh/uv/)
- [Ollama](https://ollama.com/)

### Run locally

```bash
# Install frontend deps
npm install

# Start the sidecar
cd sidecar
pip install agentarmor-core[all]
python main.py

# In another terminal, start the frontend
npm run dev
```

### Build installer

Tagged commits trigger GitHub Actions to build the NSIS installer automatically. See `.github/workflows/release.yml`.

## Related

- [agentarmor-core](https://github.com/Agastya910/agentarmor) - The underlying 8-layer security framework (also on [PyPI](https://pypi.org/project/agentarmor-core/))
- [OWASP Top 10 for Agentic Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

## License

Apache 2.0
