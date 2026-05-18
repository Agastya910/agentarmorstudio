/**
 * AgentArmor Studio — Typed API client
 *
 * Communicates with the Python FastAPI sidecar running on a random local port.
 * The port is discovered via the `get_sidecar_port` Tauri command.
 */
// ---------------------------------------------------------------------------
// Port discovery
// ---------------------------------------------------------------------------

/** Default port used in browser dev mode (when not inside Tauri). */
const DEV_FALLBACK_PORT = 8457;

let _cachedPort: number | null = null;

/** Detect whether we're running inside a Tauri webview. */
function isTauri(): boolean {
  return typeof window !== "undefined" && !!(window as any).__TAURI_INTERNALS__;
}

/** Read the sidecar port — from Tauri in production, fallback in dev. */
async function getSidecarPort(): Promise<number> {
  if (_cachedPort !== null) return _cachedPort;

  if (isTauri()) {
    // Dynamic import so the module isn't required in pure-browser mode
    const { invoke } = await import("@tauri-apps/api/core");
    const port = await invoke<number>("get_sidecar_port");
    _cachedPort = port;
    return port;
  }

  // Browser dev mode — use the fixed fallback port
  _cachedPort = DEV_FALLBACK_PORT;
  return _cachedPort;
}

/** Build the base URL for the sidecar. */
async function baseUrl(): Promise<string> {
  const port = await getSidecarPort();
  return `http://127.0.0.1:${port}`;
}

// ---------------------------------------------------------------------------
// Generic fetch helper
// ---------------------------------------------------------------------------

export async function apiFetch<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const base = await baseUrl();
  const { headers: optHeaders, ...rest } = options;
  const res = await fetch(`${base}${path}`, {
    ...rest,
    headers: {
      "Content-Type": "application/json",
      ...(optHeaders as Record<string, string>),
    },
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`API ${res.status}: ${body}`);
  }
  return res.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

export interface LayerStatus {
  name: string;
  enabled: boolean;
}

export interface StatusResponse {
  status: string;
  version: string;
  layers: LayerStatus[];
  total_layers: number;
}

export interface SecurityEvent {
  type: string;
  event_id: string;
  agent_id: string;
  [key: string]: unknown;
}

export interface EventsResponse {
  events: SecurityEvent[];
  count: number;
}

export interface LayerDetail {
  layer: string;
  verdict: string;
  threat_level: string;
  message: string;
  // Populated by the sidecar for the per-layer expand panel:
  details?: Record<string, unknown>;
  latency_ms?: number;
  timestamp?: string;
  // L1-specific fields surfaced for the Studio layer-row drill-down.
  matched_patterns?: string[];
  similarity_scores?: Record<string, number>;
  anomalies?: Array<Record<string, unknown>>;
  started_at?: string;
  completed_at?: string;
}

export interface ScanResponse {
  verdict: string;
  threat_level: string;
  is_safe: boolean;
  blocked_by: string | null;
  processing_time_ms: number;
  layers: LayerDetail[];
}

export interface AgentRunResponse {
  verdict: string;
  threat_level: string;
  is_safe: boolean;
  blocked_by: string | null;
  processing_time_ms: number;
  layers: LayerDetail[];
}

export interface OllamaModel {
  name: string;
  size: number;
  modified_at: string;
}

export interface OllamaModelsResponse {
  models: OllamaModel[];
  error?: string;
}

export interface OllamaAgentRunRequest {
  model: string;
  system_prompt: string;
  user_message: string;
  layers_enabled: number[];
  conversation_history?: Array<{ role: string; content: string }>;
  agent_id?: string;
}

export interface ToolCallLog {
  tool: string;
  args: Record<string, unknown>;
  timestamp: string;
  blocked: boolean;
  blocked_by?: string | null;
  result?: string;
  security_events?: LayerDetail[];
}

export interface OllamaAgentRunResponse {
  response: string;
  blocked: boolean;
  blocked_by: string | null;
  error?: string;
  events: LayerDetail[];
  tool_calls: ToolCallLog[];
  latency_ms: number;
  security_overhead_ms: number;
}

export interface ToolInfo {
  name: string;
  description: string;
  action: string;
  parameters: Record<string, unknown>;
}

export interface ToolsResponse {
  tools: ToolInfo[];
  count: number;
}

export interface LayerConfig {
  [key: string]: unknown;
}

export interface LayersResponse {
  ingestion: LayerConfig;
  storage: LayerConfig;
  context: LayerConfig;
  planning: LayerConfig;
  execution: LayerConfig;
  output: LayerConfig;
  interagent: LayerConfig;
  identity: LayerConfig;
  audit: LayerConfig;
}

// ---------------------------------------------------------------------------
// API methods
// ---------------------------------------------------------------------------

/** GET /status — layer health & pipeline readiness */
export async function getStatus(): Promise<StatusResponse> {
  return apiFetch<StatusResponse>("/status");
}

/** GET /events — last N security events */
export async function getEvents(limit = 100): Promise<EventsResponse> {
  return apiFetch<EventsResponse>(`/events?limit=${limit}`);
}

/** POST /scan — scan a prompt through the pipeline */
export async function scanPrompt(
  text: string,
  agentId = "studio",
): Promise<ScanResponse> {
  return apiFetch<ScanResponse>("/scan", {
    method: "POST",
    body: JSON.stringify({ text, agent_id: agentId }),
  });
}

/** POST /agent/run — run a wrapped agent call */
export async function runAgent(payload: {
  action: string;
  params?: Record<string, unknown>;
  agent_id?: string;
  context?: Record<string, unknown>;
  input_data?: unknown;
  output_data?: unknown;
}): Promise<AgentRunResponse> {
  return apiFetch<AgentRunResponse>("/agent/run", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

/** GET /layers — per-layer configuration */
export async function getLayers(): Promise<LayersResponse> {
  return apiFetch<LayersResponse>("/layers");
}

/** GET /ollama/models — list locally available Ollama models */
export async function getOllamaModels(): Promise<OllamaModelsResponse> {
  return apiFetch<OllamaModelsResponse>("/ollama/models");
}

/** GET /tools — list available agent tools */
export async function getTools(): Promise<ToolsResponse> {
  return apiFetch<ToolsResponse>("/tools");
}

/** POST /agent/run — run an AgentArmor-wrapped Ollama agent call */
export async function runOllamaAgent(
  payload: OllamaAgentRunRequest,
): Promise<OllamaAgentRunResponse> {
  return apiFetch<OllamaAgentRunResponse>("/agent/run", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export type SSEEventType =
  | "layer_start"
  | "layer_check"
  | "layer_complete"
  | "llm_request_start"
  | "llm_response"
  | "tool_start"
  | "tool_result"
  | "final"
  | "error";

export interface SSEEvent {
  type: SSEEventType;
  [key: string]: unknown;
}

/** Returned by runOllamaAgentStream so callers can mid-run abort. */
export interface StreamHandle {
  /** Promise that resolves with the final response or rejects on error/abort. */
  result: Promise<OllamaAgentRunResponse>;
  /** Aborts the in-flight stream. The result promise rejects with an AbortError. */
  abort: () => void;
}

/** POST /agent/run/stream — streaming SSE version.
 *  Calls onEvent for each event as it fires.
 *  Returns a {result, abort} handle so the UI can cancel a long-running run.
 */
export function runOllamaAgentStream(
  payload: OllamaAgentRunRequest,
  onEvent: (event: SSEEvent) => void,
): StreamHandle {
  const controller = new AbortController();

  const result = (async () => {
    const base = await baseUrl();
    const resp = await fetch(`${base}/agent/run/stream`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    if (!resp.ok || !resp.body) {
      throw new Error(`Stream request failed: ${resp.status}`);
    }

    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let finalPayload: OllamaAgentRunResponse | null = null;

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      // SSE lines are "data: {...}\n\n"
      const parts = buffer.split("\n\n");
      buffer = parts.pop() ?? "";

      for (const part of parts) {
        const line = part.trim();
        if (!line.startsWith("data:")) continue;
        try {
          const event = JSON.parse(line.slice(5).trim()) as SSEEvent;
          onEvent(event);
          if (event.type === "final") {
            finalPayload = event as unknown as OllamaAgentRunResponse;
          }
        } catch { /* skip malformed */ }
      }
    }

    if (!finalPayload) throw new Error("Stream ended without a final event");
    return finalPayload;
  })();

  return { result, abort: () => controller.abort() };
}



// ---------------------------------------------------------------------------
// Agent Registry types & methods
// ---------------------------------------------------------------------------

export interface RegisteredAgent {
  agent_id: string;
  framework: string;
  agent_type: string;
  registered_at: string;
  last_heartbeat: string;
  status: "online" | "offline" | "error";
  events_count: number;
  blocked_count: number;
  permissions: string[];
}

export interface AgentsResponse {
  agents: RegisteredAgent[];
  count: number;
}

export interface ApiKeyResponse {
  api_key: string;
  key_file?: string;
  message?: string;
}

/** GET /agents — list all registered agents */
export async function getAgents(): Promise<AgentsResponse> {
  return apiFetch<AgentsResponse>("/agents");
}

/** GET /settings/api-key — get the Studio API key */
export async function getApiKey(): Promise<ApiKeyResponse> {
  return apiFetch<ApiKeyResponse>("/settings/api-key");
}

/** POST /settings/api-key/regenerate — generate new API key */
export async function regenerateApiKey(): Promise<ApiKeyResponse> {
  return apiFetch<ApiKeyResponse>("/settings/api-key/regenerate", {
    method: "POST",
  });
}

/** POST /agents/register — register an agent (requires API key) */
export async function registerAgent(
  agentId: string,
  framework: string,
  apiKey: string,
): Promise<{ success: boolean; agent_id: string; message: string }> {
  return apiFetch("/agents/register", {
    method: "POST",
    headers: { Authorization: `Bearer ${apiKey}` },
    body: JSON.stringify({
      agent_id: agentId,
      framework,
      agent_type: "general",
    }),
  });
}

/** DELETE /agents/:id — unregister an agent (requires API key) */
export async function unregisterAgent(
  agentId: string,
  apiKey: string,
): Promise<{ success: boolean; message: string }> {
  return apiFetch(`/agents/${agentId}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${apiKey}` },
  });
}
