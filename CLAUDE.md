# AgentArmor Studio

## What this is

AgentArmor Studio is a no-code interface for building AI agents that are wrapped in the AgentArmor library by default. It is the safe-by-default agent builder.

## My role here

I am Agastya Todi, the maintainer of this repo.

## How to work in this repo

- Default model: Sonnet. Switch to Opus only for cross-cutting refactors or threat-model changes.
- Default effort: low. Bump to high only when explicitly told.
- Always read this file and the file you are editing. Do not read the whole tree.
- One PR per session. Branch name: claude/studio-<slug>.
- Never push to main. Never merge. Never bump versions.

## Stack

- Desktop shell: Tauri 2 (Rust) in src-tauri/, spawning a Python sidecar (FastAPI on localhost) in sidecar/.
- Frontend: React 18 + TypeScript 5, Vite 6, Radix UI primitives, lucide-react, recharts, react-markdown.
- Styling: Tailwind CSS 3 with PostCSS and autoprefixer (tailwind.config.js, postcss.config.js).
- Sidecar Python deps: fastapi, uvicorn, httpx, tavily-python, beautifulsoup4, e2b-code-interpreter.
- agentarmor-core is consumed as a PyPI dependency pinned in desktop/sidecar/requirements.txt (not a git submodule, not a sibling path, not an npm dep).
- Scripts: `npm run dev` (tauri dev), `npm run build` (tauri build), `npm run preview` (vite preview).

## Relationship to agentarmor

This repo depends on agentarmor-core via PyPI, installed by the Python sidecar; the React frontend never imports agentarmor directly and reaches it only through localhost HTTP. Any change to the public API of agentarmor (layer classes, intercept result shape, CLI flags, MCP tool names) must be reflected in sidecar handlers and in any UI wiring that reads those shapes.

## Threat model in one paragraph

Studio defends the same surface as agentarmor-core (prompt injection, goal hijacking, tool misuse, memory poisoning, credential and PII exfiltration, multi-step attack chains, rogue agents) while adding a local attack surface: the Tauri IPC bridge, the sidecar HTTP endpoint on localhost, user-supplied API keys in settings, and SQLite state on disk. Treat every LLM output, tool response, and file path from the UI as attacker controlled. Never exec or eval dynamic strings in Rust, TypeScript, or Python.

## Layers (so Claude knows the architecture)

- L1 Ingestion: prompt injection detection (regex + ML classifier), Unicode normalization, CDR.
- L2 Storage: AES-256-GCM encryption, HMAC-SHA256 integrity on all persisted data.
- L3 Context: template injection stripping, canary tokens, goal-drift detection.
- L4 Planning: verb-risk classification, chain escalation detection, compound risk scoring.
- L5 Execution: network isolation, SSRF blocking, path traversal prevention, per-agent sandboxing.
- L6 Output: credential scanning, PII redaction (Presidio), exfiltration pattern detection.
- L7 Inter-Agent: replay prevention, delegation certificates, trust scoring, anomaly detection.
- L8 Identity: API key validation, RBAC, session binding, permission boundaries.

## What NOT to touch without asking

- SECURITY.md, LICENSE, /docs/public/\*
- Release workflows, version bumps (package.json version, src-tauri/Cargo.toml, tauri.conf.json).
- Anything in a directory whose name starts with vendor/.
- Marketing copy on the landing page, any analytics IDs, the demo flow.

## Tests and CI

- Frontend dev loop: `npm run dev`. Production build: `npm run build`.
- Sidecar run: `cd sidecar && pip install -r requirements.txt && python main.py`.
- Release CI: `.github/workflows/release.yml` builds Windows NSIS, Ubuntu, and macOS aarch64 installers on `desktop-v*` tags via tauri-action.
- TODO: no automated unit test runner is wired into package.json.

## When you finish

Post a 5-bullet summary in the PR description: what changed, why, files touched, tests added, follow-ups. Stop. Do not start another task.
