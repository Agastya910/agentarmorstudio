# AgentArmor Studio — Desktop Application

**Private repository** for the AgentArmor Studio desktop application. This is the user-facing companion app for the [AgentArmor](https://github.com/Agastya910/agentarmor) security library.

## What is AgentArmor Studio?

AgentArmor Studio is a Tauri-based desktop application that provides:

- 🤖 **Agent Runner** — Chat with AI agents (Ollama, OpenAI, Anthropic) with all 8 security layers enforced in real-time
- 🛠️ **Agent Builder** — Visually assemble and deploy custom LangGraph agents with configurable security layers, tools, and network policies
- 📊 **Event Monitor** — Real-time security event dashboard showing layer verdicts, threat levels, and audit trails
- ⚙️ **Settings** — Studio API key management, external API keys (Tavily, E2B), and L5 Network Policy controls

## Architecture

```
┌─────────────────────────────────────┐
│         Tauri Desktop Shell          │
│  ┌─────────────────────────────┐    │
│  │     React + Vite Frontend    │    │
│  │  ┌─────┬──────┬──────┬────┐ │    │
│  │  │Agent│Agent │Event │Set-│ │    │
│  │  │Run- │Build-│Moni- │ting│ │    │
│  │  │ner  │er    │tor   │s   │ │    │
│  │  └─────┴──────┴──────┴────┘ │    │
│  └──────────────┬──────────────┘    │
│                 │ HTTP (localhost)    │
│  ┌──────────────▼──────────────┐    │
│  │    Python Sidecar (FastAPI)  │    │
│  │  ┌───────────────────────┐  │    │
│  │  │  AgentArmor Pipeline   │  │    │
│  │  │  L1→L8 Security Layers │  │    │
│  │  └───────────────────────┘  │    │
│  │  ┌───────────────────────┐  │    │
│  │  │  StudioDB (SQLite)     │  │    │
│  │  │  Encrypted + MAC       │  │    │
│  │  └───────────────────────┘  │    │
│  └─────────────────────────────┘    │
└─────────────────────────────────────┘
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Desktop Shell | [Tauri](https://tauri.app/) (Rust) |
| Frontend | React + TypeScript + Vite |
| Styling | Tailwind CSS + shadcn/ui |
| Sidecar | Python + FastAPI + Uvicorn |
| Database | SQLite (AES-256-GCM encrypted) |
| AI Runtime | Ollama (local), OpenAI, Anthropic |
| Security | AgentArmor library (L1–L8) |

## Setup

### Prerequisites

- [Node.js](https://nodejs.org/) 18+
- [Rust](https://www.rust-lang.org/) (for Tauri)
- [Python](https://www.python.org/) 3.11+ with [uv](https://docs.astral.sh/uv/)
- [Ollama](https://ollama.com/) (for local AI)

### Install Dependencies

```bash
# Frontend
npm install

# Sidecar (Python)
cd sidecar
uv sync
```

### Development

```bash
# Start the sidecar separately for development
cd sidecar
uv run python main.py

# In another terminal, start the frontend
npm run dev
```

### Build for Production

```bash
npm run tauri build
```

## Security Layers Enforced

The sidecar enforces all hardened security layers on every agent interaction:

| Layer | Enforcement |
|-------|------------|
| L1 | Input scanning before LLM processing |
| L2 | AES-256-GCM encrypted SQLite storage with MAC signatures |
| L3 | GoalLock + CanaryVault + tiered context assembly |
| L4 | ActionChainTracker + semantic risk scoring on tool calls |
| L5 | 5-domain execution enforcement (DNS rebinding, rate limits, circuit breakers) |
| L6 | 5-scanner output pipeline (credentials, PII, harmful content, exfiltration) |

## Pages

### Agent Runner (`/agent-runner`)
Chat interface with real-time security event display. Supports both streaming and non-streaming responses. Shows L3 context events, L4 planning verdicts, L5 execution results, and L6 output scans inline.

### Agent Builder (`/builder`)
Visual agent configuration:
- Agent identity (name, system prompt)
- LLM provider selection (Ollama model picker, OpenAI, Anthropic)
- Tool capabilities (web search, file read, command runner)
- Security layer toggles (L1–L8)
- Network routing (isolation level, domain allowlist/blocklist)

### Event Monitor (`/events`)
Real-time security dashboard with filtering by agent, layer, and verdict.

### Settings (`/settings`)
- Studio API key management
- External API keys (Tavily, E2B)
- L5 Network Policy (HTTPS enforcement, max payload, DNS rebinding protection)
- Connected agents list

## API Endpoints

The sidecar exposes these endpoints on `http://127.0.0.1:<port>`:

| Endpoint | Description |
|----------|------------|
| `POST /agent/run` | Non-streaming agent execution |
| `POST /agent/run/stream` | Streaming agent execution (SSE) |
| `GET /agents` | List registered agents |
| `POST /builder/deploy` | Build and deploy a custom agent |
| `GET /settings/network-policy` | Get L5 network policy |
| `POST /settings/network-policy` | Save L5 network policy |
| `GET /events` | Query security events |
