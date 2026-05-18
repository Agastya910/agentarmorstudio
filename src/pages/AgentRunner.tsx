import { useCallback, useEffect, useRef, useState } from "react";
import ReactMarkdown from "react-markdown";
import {
  AlertTriangle,
  Bot,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Loader2,
  Plus,
  Send,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Square,
  Terminal,
  Trash2,
  XCircle,
  Zap,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import {
  getAgents,
  getApiKey,
  getOllamaModels,
  getSidecarLogPath,
  runOllamaAgentStream,
  unregisterAgent,
  type OllamaModel,
  type OllamaAgentRunResponse,
  type RegisteredAgent,
  type ToolCallLog,
  type LayerDetail,
  type SSEEvent,
} from "@/lib/api";

// ---------------------------------------------------------------------------
// Layer metadata
// ---------------------------------------------------------------------------

const LAYER_META = [
  { id: 1, label: "L1 Ingestion" },
  { id: 2, label: "L2 Storage" },
  { id: 3, label: "L3 Context" },
  { id: 4, label: "L4 Planning" },
  { id: 5, label: "L5 Execution" },
  { id: 6, label: "L6 Output" },
  { id: 7, label: "L7 Inter-Agent" },
  { id: 8, label: "L8 Identity" },
] as const;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ChatMessage {
  role: "user" | "assistant" | "system";
  content: string;
  timestamp: Date;
  blocked?: boolean;
  blocked_by?: string | null;
  events?: LayerDetail[];
  tool_calls?: ToolCallLog[];
  latency_ms?: number;
  security_overhead_ms?: number;
}

// ---------------------------------------------------------------------------
// Verdict helpers
// ---------------------------------------------------------------------------

function verdictIcon(v: string) {
  switch (v) {
    case "allow":
      return <CheckCircle2 className="h-3 w-3 text-emerald-400" />;
    case "deny":
      return <XCircle className="h-3 w-3 text-red-400" />;
    case "escalate":
      return <ShieldAlert className="h-3 w-3 text-amber-400" />;
    case "audit":
      return <Shield className="h-3 w-3 text-blue-400" />;
    default:
      return <Shield className="h-3 w-3 text-gray-500" />;
  }
}

function verdictColor(v: string): string {
  switch (v) {
    case "allow": return "text-emerald-400";
    case "deny": return "text-red-400";
    case "escalate": return "text-amber-400";
    case "audit": return "text-blue-400";
    default: return "text-gray-500";
  }
}

function verdictLabel(v: string): string {
  switch (v) {
    case "allow": return "ALLOW";
    case "deny": return "DENY";
    case "escalate": return "ESCALATE";
    case "audit": return "AUDIT";
    default: return v.toUpperCase();
  }
}

// ---------------------------------------------------------------------------
// Execution Timeline — shows the security pipeline for each response
// ---------------------------------------------------------------------------

function ExecutionTimeline({
  events,
  tool_calls,
  blocked,
  blocked_by,
  latency_ms,
  security_overhead_ms,
}: {
  events: LayerDetail[];
  tool_calls: ToolCallLog[];
  blocked: boolean;
  blocked_by?: string | null;
  latency_ms?: number;
  security_overhead_ms?: number;
}) {
  const [expandedTools, setExpandedTools] = useState<Set<number>>(new Set());

  const toggleTool = (idx: number) => {
    setExpandedTools((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  };

  // Separate L1 event from the rest
  const l1Event = events.find((e) => e.layer?.includes("ingestion") || e.layer?.includes("L1"));
  const l6FinalEvent = events.filter((e) => e.layer?.includes("output") || e.layer?.includes("L6")).pop();

  return (
    <div className="mt-2 space-y-0">
      {/* L1 Ingestion check */}
      {l1Event && (
        <TimelineStep
          icon={<Shield className="h-3 w-3" />}
          label="L1 Ingestion"
          verdict={l1Event.verdict}
          message={l1Event.message}
          details={l1Event.details}
          latencyMs={l1Event.latency_ms}
          isFirst
        />
      )}

      {/* If blocked at L1, show that and stop */}
      {blocked && blocked_by?.includes("ingestion") && (
        <TimelineStep
          icon={<ShieldX className="h-3 w-3" />}
          label="BLOCKED"
          verdict="deny"
          message={`Security layer ${blocked_by} blocked this request`}
          isLast
          isBlocked
        />
      )}

      {/* Tool calls — each with its own security sub-timeline */}
      {!blocked && tool_calls.map((tc, i) => (
        <div key={i}>
          {/* Tool call header */}
          <div
            className={cn(
              "flex items-center gap-2 py-1.5 pl-5 cursor-pointer hover:bg-gray-800/30 rounded transition-colors",
              tc.blocked && "opacity-80",
            )}
            onClick={() => toggleTool(i)}
          >
            <div className="w-px h-4 bg-gray-700 -ml-[9px] mr-1.5" />
            {expandedTools.has(i)
              ? <ChevronDown className="h-3 w-3 text-gray-500 flex-none" />
              : <ChevronRight className="h-3 w-3 text-gray-500 flex-none" />
            }
            <Terminal className="h-3 w-3 text-brand-400 flex-none" />
            <span className="font-mono text-[11px] text-gray-200">
              {tc.tool}
            </span>
            <span className="text-[10px] text-gray-600 truncate flex-1">
              ({Object.entries(tc.args).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(", ").slice(0, 80)})
            </span>
            {tc.blocked ? (
              <span className="text-[9px] font-semibold text-red-400 bg-red-500/10 px-1.5 py-0.5 rounded">BLOCKED</span>
            ) : (
              <span className="text-[9px] font-semibold text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded">OK</span>
            )}
          </div>

          {/* Expanded: per-tool security sub-timeline */}
          {expandedTools.has(i) && (
            <div className="pl-10 space-y-0 mb-1">
              {tc.security_events?.map((se, j) => (
                <TimelineStep
                  key={j}
                  icon={verdictIcon(se.verdict)}
                  label={se.layer || "Security"}
                  verdict={se.verdict}
                  message={se.message}
                  small
                />
              ))}
              {!tc.blocked && (
                <TimelineStep
                  icon={<Zap className="h-3 w-3 text-brand-400" />}
                  label="Executed"
                  verdict="allow"
                  message=""
                  small
                />
              )}
              {tc.result && !tc.blocked && (
                <div className="ml-5 mt-1 mb-2">
                  <pre className="text-[10px] text-gray-400 bg-gray-900/80 rounded p-2 overflow-x-auto max-h-24 overflow-y-auto whitespace-pre-wrap border border-gray-800/50">
                    {tc.result}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>
      ))}

      {/* L6 final output scan */}
      {!blocked && l6FinalEvent && (
        <TimelineStep
          icon={<Shield className="h-3 w-3" />}
          label="L6 Output"
          verdict={l6FinalEvent.verdict}
          message={l6FinalEvent.message}
          details={l6FinalEvent.details}
          latencyMs={l6FinalEvent.latency_ms}
        />
      )}

      {/* Summary line */}
      <div className="flex items-center gap-2 pt-1.5 pl-5 text-[10px] text-gray-600">
        <div className="w-px h-3 bg-gray-800 -ml-[9px] mr-1.5" />
        {latency_ms !== undefined && latency_ms > 0 && (
          <span>
            <span className="text-gray-500 font-mono">{latency_ms}ms</span> total
          </span>
        )}
        {security_overhead_ms !== undefined && security_overhead_ms > 0 && (
          <span>
            • <span className="text-gray-500 font-mono">{security_overhead_ms}ms</span> security
          </span>
        )}
        {tool_calls.length > 0 && (
          <span>
            • {tool_calls.length} tool{tool_calls.length !== 1 ? "s" : ""} called
            {tool_calls.filter((t) => t.blocked).length > 0 && (
              <span className="text-red-400">
                {" "}({tool_calls.filter((t) => t.blocked).length} blocked)
              </span>
            )}
          </span>
        )}
      </div>
    </div>
  );
}

// Single timeline step. When `details` is present, the row becomes expandable.
function TimelineStep({
  icon,
  label,
  verdict,
  message,
  isFirst,
  isLast,
  isBlocked,
  small,
  details,
  latencyMs,
}: {
  icon: React.ReactNode;
  label: string;
  verdict: string;
  message: string;
  isFirst?: boolean;
  isLast?: boolean;
  isBlocked?: boolean;
  small?: boolean;
  details?: Record<string, unknown>;
  latencyMs?: number;
}) {
  const [expanded, setExpanded] = useState(false);
  const expandable = details !== undefined && Object.keys(details).length > 0;

  return (
    <div>
      <div
        className={cn(
          "flex items-center gap-2 pl-5 relative",
          small ? "py-0.5" : "py-1.5",
          expandable && "cursor-pointer hover:bg-gray-800/30 rounded transition-colors",
        )}
        onClick={expandable ? () => setExpanded((e) => !e) : undefined}
      >
        {/* Vertical connector line */}
        {!isFirst && <div className="absolute left-[11px] -top-0 w-px h-2 bg-gray-700" />}
        {!isLast && <div className="absolute left-[11px] bottom-0 w-px h-2 bg-gray-700" />}

        {/* Chevron (only when expandable) */}
        {expandable && (
          expanded
            ? <ChevronDown className="h-3 w-3 text-gray-500 flex-none -ml-3" />
            : <ChevronRight className="h-3 w-3 text-gray-500 flex-none -ml-3" />
        )}

        {/* Node dot */}
        <div className={cn(
          "flex-none -ml-[9px] mr-1.5",
          small ? "opacity-70" : "",
        )}>
          {icon}
        </div>

        {/* Label + verdict */}
        <span className={cn("font-mono flex-none", small ? "text-[10px] text-gray-500" : "text-[11px] text-gray-400")}>
          {label}
        </span>
        <span className="text-[10px] text-gray-700">──</span>
        <span className={cn("text-[10px] font-semibold", verdictColor(verdict), isBlocked && "animate-pulse")}>
          {verdictLabel(verdict)}
        </span>
        {message && (
          <span className="text-[10px] text-gray-600 truncate">{message}</span>
        )}
        {latencyMs !== undefined && (
          <span className="text-[9px] text-gray-700 font-mono ml-auto pr-2">{latencyMs}ms</span>
        )}
      </div>

      {expandable && expanded && (
        <LayerDetailsPanel details={details!} />
      )}
    </div>
  );
}

// Drill-down panel showing detector-level findings for a layer.
function LayerDetailsPanel({ details }: { details: Record<string, unknown> }) {
  const defensesApplied = details["defenses_applied"] as string[] | undefined;
  const anomalies = details["anomalies_found"] as Array<Record<string, unknown>> | undefined;
  const regexMatches = details["regex_categories_matched"] as string[] | undefined;
  const embeddingSim = details["embedding_similarity"] as number | undefined;
  const embeddingTemplate = details["embedding_match_template"] as string | undefined;
  const embeddingCategory = details["embedding_match_category"] as string | undefined;
  const classifierLabel = details["classifier_label"] as string | undefined;
  const classifierConf = details["classifier_confidence"] as number | undefined;
  const perplexity = details["perplexity_score"] as number | undefined;
  const findings = details["findings"] as Array<Record<string, unknown>> | undefined;

  return (
    <div className="ml-10 mt-1 mb-2 px-3 py-2 bg-gray-900/50 border border-gray-800 rounded space-y-1 text-[10px] text-gray-400 font-mono">
      {defensesApplied && defensesApplied.length > 0 && (
        <div>
          <span className="text-gray-600">defenses:</span>{" "}
          <span className="text-brand-300">{defensesApplied.join(" → ")}</span>
        </div>
      )}
      {regexMatches && regexMatches.length > 0 && (
        <div>
          <span className="text-gray-600">D2 regex hits:</span>{" "}
          <span className="text-amber-300">{regexMatches.join(", ")}</span>
        </div>
      )}
      {embeddingSim !== undefined && (
        <div>
          <span className="text-gray-600">D5 embedding similarity:</span>{" "}
          <span className={cn(
            "font-semibold",
            embeddingSim >= 0.85 ? "text-red-400" :
              embeddingSim >= 0.70 ? "text-amber-400" : "text-emerald-400",
          )}>{embeddingSim.toFixed(3)}</span>
          {embeddingCategory && (
            <span className="text-gray-600"> · {embeddingCategory}</span>
          )}
        </div>
      )}
      {embeddingTemplate && (
        <div className="text-gray-500 italic truncate" title={embeddingTemplate}>
          ↳ "{embeddingTemplate.slice(0, 90)}{embeddingTemplate.length > 90 ? "…" : ""}"
        </div>
      )}
      {classifierLabel && classifierLabel !== "UNKNOWN" && (
        <div>
          <span className="text-gray-600">D3 classifier:</span>{" "}
          <span className="text-blue-300">{classifierLabel}</span>
          {classifierConf !== undefined && (
            <span className="text-gray-600"> ({(classifierConf * 100).toFixed(1)}%)</span>
          )}
        </div>
      )}
      {perplexity !== undefined && perplexity !== null && perplexity > 0 && (
        <div>
          <span className="text-gray-600">D4 perplexity:</span>{" "}
          <span className={cn(
            "font-semibold",
            perplexity > 1000 ? "text-red-400" : "text-emerald-400",
          )}>{perplexity.toFixed(1)}</span>
        </div>
      )}
      {anomalies && anomalies.length > 0 && (
        <div>
          <span className="text-gray-600">anomalies ({anomalies.length}):</span>
          <ul className="ml-3 mt-0.5 space-y-0.5">
            {anomalies.slice(0, 5).map((a, i) => (
              <li key={i} className="text-gray-500">
                · {String(a.type ?? "?")}
                {a.category !== undefined && <span className="text-gray-600"> [{String(a.category)}]</span>}
                {a.severity !== undefined && <span className="text-amber-500/80"> sev={String(a.severity)}</span>}
                {a.matched_text !== undefined && (
                  <span className="text-gray-600 italic"> · "{String(a.matched_text).slice(0, 50)}"</span>
                )}
              </li>
            ))}
            {anomalies.length > 5 && (
              <li className="text-gray-700">… +{anomalies.length - 5} more</li>
            )}
          </ul>
        </div>
      )}
      {findings && findings.length > 0 && (
        <div>
          <span className="text-gray-600">L6 findings ({findings.length}):</span>
          <ul className="ml-3 mt-0.5 space-y-0.5">
            {findings.slice(0, 5).map((f, i) => (
              <li key={i} className="text-gray-500">
                · {String(f.type ?? f.entity_type ?? "?")}
                {f.severity !== undefined && <span className="text-amber-500/80"> sev={String(f.severity)}</span>}
                {f.matched_text !== undefined && (
                  <span className="text-gray-600 italic"> · "{String(f.matched_text).slice(0, 50)}"</span>
                )}
              </li>
            ))}
            {findings.length > 5 && (
              <li className="text-gray-700">… +{findings.length - 5} more</li>
            )}
          </ul>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Framework label helpers
// ---------------------------------------------------------------------------

const FRAMEWORK_LABELS: Record<string, string> = {
  "built-in": "Built-in",
  mcp: "MCP",
  langchain: "LangChain",
  openai: "OpenAI",
  custom: "Custom",
};

function frameworkColor(f: string): string {
  switch (f) {
    case "mcp": return "bg-purple-500/10 text-purple-400 border-purple-500/20";
    case "langchain": return "bg-teal-500/10 text-teal-400 border-teal-500/20";
    case "openai": return "bg-green-500/10 text-green-400 border-green-500/20";
    case "built-in": return "bg-brand-500/10 text-brand-400 border-brand-500/20";
    default: return "bg-gray-500/10 text-gray-400 border-gray-500/20";
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function AgentRunner({ onNavigate }: { onNavigate?: (page: string) => void }) {
  const [ollamaOnline, setOllamaOnline] = useState<boolean | null>(null);
  const [models, setModels] = useState<OllamaModel[]>([]);
  const [selectedModel, setSelectedModel] = useState("");
  const [selectedAgent, setSelectedAgent] = useState("studio");
  const [externalAgents, setExternalAgents] = useState<RegisteredAgent[]>([]);
  const [systemPrompt, setSystemPrompt] = useState(
    "You are a helpful assistant with access to tools. Use them when needed to answer questions, look up information, manage files, and complete tasks.",
  );
  const [enabledLayers, setEnabledLayers] = useState<Set<number>>(
    new Set([1, 2, 3, 4, 5, 6, 7, 8]),
  );

  const [messages, setMessages] = useState<ChatMessage[]>([]);

  // Load chat history when selected agent changes
  useEffect(() => {
    const saved = localStorage.getItem(`chat_${selectedAgent}`);
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        setMessages(parsed.map((msg: any) => ({
          ...msg,
          timestamp: new Date(msg.timestamp)
        })));
      } catch {
        setMessages([]);
      }
    } else {
      setMessages([]);
    }
  }, [selectedAgent]);

  // Save chat history when messages change
  useEffect(() => {
    if (messages.length > 0) {
      localStorage.setItem(`chat_${selectedAgent}`, JSON.stringify(messages));
    } else {
      localStorage.removeItem(`chat_${selectedAgent}`);
    }
  }, [messages, selectedAgent]);

  const clearChat = () => {
    setMessages([]);
    localStorage.removeItem(`chat_${selectedAgent}`);
  };
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);

  // Live run state — what's currently running so the UI can show progress.
  interface RunState {
    layer?: string;       // e.g. "L1_ingestion"
    layerMessage?: string;
    llmModel?: string;
    llmStartedAt?: number;
    runStartedAt?: number;
  }
  const [runState, setRunState] = useState<RunState>({});

  // Stuck-detection: track last SSE event timestamp; if no event for >20s, warn.
  const [stuck, setStuck] = useState(false);
  const lastEventTsRef = useRef<number>(0);

  // Abort handle for the active stream.
  const abortRef = useRef<(() => void) | null>(null);

  // Ticking timer for the loading-strip elapsed display.
  const [, setNowTick] = useState(0);
  useEffect(() => {
    if (!loading) return;
    const id = setInterval(() => setNowTick(t => t + 1), 500);
    return () => clearInterval(id);
  }, [loading]);

  // Stuck-detection effect: if no SSE event arrives within 20s of an active run, surface a warning.
  useEffect(() => {
    if (!loading) {
      setStuck(false);
      return;
    }
    const id = setInterval(() => {
      const last = lastEventTsRef.current;
      if (last > 0 && Date.now() - last > 20_000) {
        setStuck(true);
      }
    }, 2000);
    return () => clearInterval(id);
  }, [loading]);

  const chatEndRef = useRef<HTMLDivElement>(null);

  // ---------------------------------------------------------------------------
  // Ollama discovery
  // ---------------------------------------------------------------------------

  const checkOllama = useCallback(async () => {
    try {
      const resp = await getOllamaModels();
      if (resp.error) {
        setOllamaOnline(false);
        setModels([]);
      } else {
        setOllamaOnline(true);
        setModels(resp.models);
        if (!selectedModel && resp.models.length > 0) {
          setSelectedModel(resp.models[0].name);
        }
      }
    } catch {
      setOllamaOnline(false);
      setModels([]);
    }
  }, [selectedModel]);

  useEffect(() => {
    checkOllama();
    const id = setInterval(checkOllama, 8_000);
    return () => clearInterval(id);
  }, [checkOllama]);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // Poll for connected agents
  useEffect(() => {
    const fetchAgents = async () => {
      try {
        const resp = await getAgents();
        setExternalAgents(resp.agents.filter((a) => a.agent_id !== "studio"));
      } catch { /* sidecar not available */ }
    };
    fetchAgents();
    const id = setInterval(fetchAgents, 5_000);
    return () => clearInterval(id);
  }, []);

  const handleDeleteAgent = async (e: React.MouseEvent, agentId: string) => {
    e.stopPropagation(); // prevent selecting the agent
    try {
      const keyResp = await getApiKey();
      await unregisterAgent(agentId, keyResp.api_key);
      if (selectedAgent === agentId) setSelectedAgent("studio");
      setExternalAgents((prev) => prev.filter((a) => a.agent_id !== agentId));
    } catch { /* */ }
  };

  // ---------------------------------------------------------------------------
  // Send message
  // ---------------------------------------------------------------------------

  const handleSend = async () => {
    const text = input.trim();
    if (!text || !selectedModel || loading) return;

    const userMsg: ChatMessage = { role: "user", content: text, timestamp: new Date() };
    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setLoading(true);

    // Insert a live placeholder that we'll update as SSE events arrive
    const placeholderMsg: ChatMessage = {
      role: "assistant",
      content: "",
      timestamp: new Date(),
      events: [],
      tool_calls: [],
    };
    setMessages((prev) => [...prev, placeholderMsg]);

    // Accumulate live state during streaming
    const liveEvents: LayerDetail[] = [];
    const liveToolCalls: ToolCallLog[] = [];
    let pendingToolName = "";

    const onEvent = (event: SSEEvent) => {
      lastEventTsRef.current = Date.now();
      setStuck(false);
      if (event.type === "layer_start") {
        setRunState((prev) => ({
          ...prev,
          layer: String(event.layer ?? ""),
          layerMessage: String(event.message ?? ""),
        }));
      } else if (event.type === "layer_complete") {
        setRunState((prev) => (prev.layer === event.layer ? { ...prev, layer: undefined, layerMessage: undefined } : prev));
      } else if (event.type === "llm_request_start") {
        setRunState((prev) => ({
          ...prev,
          llmModel: String(event.model ?? ""),
          llmStartedAt: Date.now(),
        }));
      } else if (event.type === "llm_response") {
        setRunState((prev) => ({ ...prev, llmModel: undefined, llmStartedAt: undefined }));
      } else if (event.type === "layer_check") {
        liveEvents.push(event as unknown as LayerDetail);
        setMessages((prev) => {
          const next = [...prev];
          const last = { ...next[next.length - 1] };
          last.events = [...liveEvents];
          next[next.length - 1] = last;
          return next;
        });
      } else if (event.type === "tool_start") {
        pendingToolName = String(event.tool ?? "");
        setMessages((prev) => {
          const next = [...prev];
          const last = { ...next[next.length - 1] };
          last.content = `🔧 Calling ${pendingToolName}...`;
          next[next.length - 1] = last;
          return next;
        });
      } else if (event.type === "tool_result") {
        const tc: ToolCallLog = {
          tool: String(event.tool ?? ""),
          args: (event.args ?? {}) as Record<string, unknown>,
          blocked: Boolean(event.blocked),
          blocked_by: (event.blocked_by as string) ?? undefined,
          result: String(event.result ?? ""),
          timestamp: String(event.timestamp ?? ""),
          security_events: [],
        };
        liveToolCalls.push(tc);
        setMessages((prev) => {
          const next = [...prev];
          const last = { ...next[next.length - 1] };
          last.tool_calls = [...liveToolCalls];
          last.content = `🔧 ${liveToolCalls.length} tool(s) called...`;
          next[next.length - 1] = last;
          return next;
        });
      } else if (event.type === "final") {
        const resp = event as unknown as OllamaAgentRunResponse;
        setMessages((prev) => {
          const next = [...prev];
          next[next.length - 1] = {
            role: "assistant",
            content: resp.response || (resp.blocked ? `⛔ Blocked by ${resp.blocked_by}` : ""),
            timestamp: new Date(),
            blocked: resp.blocked,
            blocked_by: resp.blocked_by,
            events: resp.events ?? liveEvents,
            tool_calls: resp.tool_calls ?? liveToolCalls,
            latency_ms: resp.latency_ms,
            security_overhead_ms: resp.security_overhead_ms,
          };
          return next;
        });
      } else if (event.type === "error") {
        const msg = String(event.message ?? "Unknown error");
        // First write the error synchronously so the user sees it immediately,
        // then upgrade with the log file path once Tauri resolves it.
        setMessages((prev) => {
          const next = [...prev];
          next[next.length - 1] = {
            role: "assistant",
            content: `❌ Sidecar error: ${msg}`,
            timestamp: new Date(),
            blocked: true,
            blocked_by: "stream_error",
            events: liveEvents,
            tool_calls: liveToolCalls,
          };
          return next;
        });
        getSidecarLogPath().then((logPath) => {
          setMessages((prev) => {
            const next = [...prev];
            const last = { ...next[next.length - 1] };
            last.content = `❌ Sidecar error: ${msg}\n\n_Logs: ${logPath}_`;
            next[next.length - 1] = last;
            return next;
          });
        });
      }
    };

    lastEventTsRef.current = Date.now();
    setRunState({ runStartedAt: Date.now() });
    setStuck(false);

    const handle = runOllamaAgentStream({
      model: selectedModel,
      system_prompt: systemPrompt,
      user_message: text,
      conversation_history: messages.map(m => ({ role: m.role, content: m.content })).slice(-10),
      layers_enabled: Array.from(enabledLayers),
      agent_id: selectedAgent,
    }, onEvent);
    abortRef.current = handle.abort;

    try {
      await handle.result;
    } catch (err) {
      const isAbort = err instanceof Error && err.name === "AbortError";
      const errMsg = err instanceof Error ? err.message : String(err);
      const logPath = await getSidecarLogPath().catch(() => "%TEMP%/agentarmor_sidecar.log");
      setMessages((prev) => {
        const next = [...prev];
        next[next.length - 1] = {
          role: "assistant",
          content: isAbort
            ? "⏹ Cancelled by user"
            : `❌ Error: ${errMsg}\n\n_Logs: ${logPath}_`,
          timestamp: new Date(),
          blocked: true,
          blocked_by: isAbort ? "user_cancelled" : "client_error",
          events: liveEvents,
          tool_calls: liveToolCalls,
        };
        return next;
      });
    } finally {
      setLoading(false);
      setRunState({});
      setStuck(false);
      abortRef.current = null;
    }
  };

  const handleCancel = () => {
    abortRef.current?.();
  };

  const toggleLayer = (id: number) => {
    setEnabledLayers((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  return (
    <div className="flex gap-6 h-full min-h-0">
      {/* ── Left Panel ── */}
      <div className="w-80 flex-none flex flex-col gap-4 overflow-y-auto pr-1">
        {/* Agent Selector */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-sm">
              <Bot className="h-4 w-4" />
              Agent
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {/* Built-in Demo Agent */}
            <button
              onClick={() => setSelectedAgent("studio")}
              className={cn(
                "w-full text-left rounded-lg border p-3 transition-all",
                selectedAgent === "studio"
                  ? "border-brand-500/50 bg-brand-500/5"
                  : "border-gray-800 bg-gray-900/50 hover:border-gray-700",
              )}
            >
              <div className="flex items-center gap-2">
                <div className={cn(
                  "h-2 w-2 rounded-full",
                  ollamaOnline ? "bg-emerald-400 animate-pulse" : "bg-gray-600",
                )} />
                <span className="text-xs font-medium text-gray-200">Demo Agent (Ollama)</span>
                <Badge className={cn("ml-auto text-[9px] px-1.5 py-0 border", frameworkColor("built-in"))}>Built-in</Badge>
              </div>
              <p className="text-[10px] text-gray-500 mt-1 ml-4">Tool-calling agent using local Ollama</p>
            </button>

            {/* Connected External Agents */}
            {externalAgents.map((agent) => (
              <button
                key={agent.agent_id}
                onClick={() => setSelectedAgent(agent.agent_id)}
                className={cn(
                  "w-full text-left rounded-lg border p-3 transition-all",
                  selectedAgent === agent.agent_id
                    ? "border-brand-500/50 bg-brand-500/5"
                    : "border-gray-800 bg-gray-900/50 hover:border-gray-700",
                )}
              >
                <div className="flex items-center gap-2">
                  <div className={cn(
                    "h-2 w-2 rounded-full",
                    agent.status === "online" ? "bg-emerald-400 animate-pulse" : "bg-gray-600",
                  )} />
                  <span className="text-xs font-medium text-gray-200">{agent.agent_id}</span>
                  <Badge className={cn("ml-auto text-[9px] px-1.5 py-0 border", frameworkColor(agent.framework))}>
                    {FRAMEWORK_LABELS[agent.framework] || agent.framework}
                  </Badge>
                </div>
                <div className="flex items-center gap-3 mt-1 ml-4">
                  <span className="text-[10px] text-gray-500">
                    {agent.events_count} event{agent.events_count !== 1 ? "s" : ""}
                  </span>
                  {agent.blocked_count > 0 && (
                    <span className="text-[10px] text-red-400">
                      {agent.blocked_count} blocked
                    </span>
                  )}
                  <span className={cn(
                    "text-[10px]",
                    agent.status === "online" ? "text-emerald-500" : "text-gray-600",
                  )}>
                    {agent.status}
                  </span>
                  <div className="ml-auto">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={(e) => handleDeleteAgent(e, agent.agent_id)}
                      className="text-gray-600 hover:text-red-400 h-6 w-6 p-0 hover:bg-red-400/10"
                      title="Unregister Agent"
                    >
                      <Trash2 className="h-3 w-3" />
                    </Button>
                  </div>
                </div>
              </button>
            ))}

            {/* Connect Your Agent */}
            <button
              onClick={() => onNavigate?.("integration")}
              className="w-full text-left rounded-lg border border-dashed border-gray-700 p-3 hover:border-brand-500/30 hover:bg-brand-500/5 transition-all group"
            >
              <div className="flex items-center gap-2">
                <Plus className="h-3.5 w-3.5 text-gray-600 group-hover:text-brand-400 transition-colors" />
                <span className="text-xs text-gray-500 group-hover:text-gray-300 transition-colors">
                  Connect Your Agent
                </span>
              </div>
              <p className="text-[10px] text-gray-600 mt-1 ml-6">
                LangChain, OpenAI, MCP, Custom Python
              </p>
            </button>

            {/* Ollama status (only when demo agent selected) */}
            {selectedAgent === "studio" && (
              <>
                {ollamaOnline === null ? (
                  <div className="flex items-center gap-2 text-xs text-gray-500">
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    Connecting to Ollama…
                  </div>
                ) : ollamaOnline ? (
                  <div className="space-y-2">
                    <div className="flex items-center gap-2 text-xs text-emerald-400">
                      <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
                      Connected • {models.length} model{models.length !== 1 ? "s" : ""}
                    </div>
                    <select
                      value={selectedModel}
                      onChange={(e) => setSelectedModel(e.target.value)}
                      disabled={models.length === 0}
                      className="w-full h-8 rounded-lg border border-gray-700 bg-gray-900 px-2.5 text-xs text-gray-200 focus:outline-none focus:ring-1 focus:ring-brand-500 disabled:opacity-50"
                    >
                      {models.map((m) => <option key={m.name} value={m.name}>{m.name}</option>)}
                    </select>
                  </div>
                ) : (
                  <div className="space-y-2">
                    <div className="flex items-center gap-2 text-xs text-red-400">
                      <span className="h-2 w-2 rounded-full bg-red-400" />
                      Ollama not detected
                    </div>
                    <a href="https://ollama.com" target="_blank" rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-[10px] text-amber-400 hover:text-amber-300 underline underline-offset-2">
                      Install Ollama <ExternalLink className="h-3 w-3" />
                    </a>
                  </div>
                )}
              </>
            )}
          </CardContent>
        </Card>

        {/* System prompt */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm">System Prompt</CardTitle>
          </CardHeader>
          <CardContent>
            <textarea
              value={systemPrompt}
              onChange={(e) => setSystemPrompt(e.target.value)}
              rows={3}
              className="w-full rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-xs text-gray-200 placeholder:text-gray-600 focus:outline-none focus:ring-1 focus:ring-brand-500 resize-none"
              placeholder="System instructions…"
            />
          </CardContent>
        </Card>

        {/* Layer toggles */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm">Security Layers</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {LAYER_META.map((l) => (
              <label key={l.id} className="flex items-center justify-between cursor-pointer group">
                <span className="text-xs text-gray-400 group-hover:text-gray-200 transition-colors">{l.label}</span>
                <button
                  type="button"
                  role="switch"
                  aria-checked={enabledLayers.has(l.id)}
                  onClick={() => toggleLayer(l.id)}
                  className={cn(
                    "relative inline-flex h-5 w-9 items-center rounded-full transition-colors",
                    enabledLayers.has(l.id) ? "bg-brand-600" : "bg-gray-700",
                  )}
                >
                  <span className={cn(
                    "inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform",
                    enabledLayers.has(l.id) ? "translate-x-[18px]" : "translate-x-[3px]",
                  )} />
                </button>
              </label>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* ── Right Panel: Chat with Execution Timelines ── */}
      <Card className="flex-1 flex flex-col min-w-0 min-h-0">
        <CardHeader className="flex-none pb-3 border-b border-gray-800/60 flex flex-row items-center justify-between">
          <CardTitle className="flex items-center gap-2 text-sm">
            <ShieldCheck className="h-4 w-4 text-brand-400" />
            Agent Runner
            {selectedModel && (
              <Badge variant="secondary" className="ml-1 text-[10px]">{selectedModel}</Badge>
            )}
          </CardTitle>
          {messages.length > 0 && (
            <Button variant="ghost" size="sm" onClick={clearChat} className="h-7 w-7 p-0 flex-none text-gray-500 hover:text-red-400 hover:bg-red-400/10" title="Clear Chat">
              <Trash2 className="h-3.5 w-3.5" />
            </Button>
          )}
        </CardHeader>

        {/* Messages */}
        <CardContent className="flex-1 overflow-y-auto p-4 space-y-4 min-h-0">
          {messages.length === 0 && (
            <div className="flex flex-col items-center justify-center h-full text-gray-600 text-xs gap-3">
              <div className="relative">
                <Bot className="h-12 w-12 text-gray-700" />
                <ShieldCheck className="h-5 w-5 text-brand-500/50 absolute -bottom-1 -right-1" />
              </div>
              <p className="text-gray-500">Send a message to run the agent with AgentArmor protection.</p>
              <p className="text-[10px] text-gray-700 max-w-md text-center">
                The agent can read/write files, query databases, search the web, send emails, run code, and more.
                Every action is checked through the security pipeline.
              </p>
            </div>
          )}

          {messages.map((msg, i) => (
            <div
              key={i}
              className={cn("flex gap-3 animate-fade-in", msg.role === "user" ? "justify-end" : "justify-start")}
            >
              <div className={cn(
                "rounded-xl px-4 py-3 text-sm",
                msg.role === "user"
                  ? "max-w-[70%] bg-brand-600/20 text-gray-100 rounded-br-sm"
                  : "max-w-[90%] bg-gray-800/60 text-gray-200 rounded-bl-sm w-full",
              )}>
                {/* Assistant: Execution Timeline */}
                {msg.role === "assistant" && msg.events && (msg.events.length > 0 || (msg.tool_calls && msg.tool_calls.length > 0)) && (
                  <ExecutionTimeline
                    events={msg.events}
                    tool_calls={msg.tool_calls || []}
                    blocked={msg.blocked || false}
                    blocked_by={msg.blocked_by}
                    latency_ms={msg.latency_ms}
                    security_overhead_ms={msg.security_overhead_ms}
                  />
                )}

                {/* Response text */}
                {msg.content && (
                  <div className={cn(
                    "text-gray-200 text-sm",
                    msg.role === "assistant" && msg.events && (msg.events.length > 0 || (msg.tool_calls && msg.tool_calls.length > 0))
                      ? "mt-3 pt-3 border-t border-gray-700/30"
                      : "",
                  )}>
                    <ReactMarkdown
                      components={{
                        p: ({node, ...props}) => <p className="mb-2 last:mb-0 break-words" {...props} />,
                        ul: ({node, ...props}) => <ul className="list-disc ml-4 mb-2" {...props} />,
                        ol: ({node, ...props}) => <ol className="list-decimal ml-4 mb-2" {...props} />,
                        li: ({node, ...props}) => <li className="mt-1" {...props} />,
                        a: ({node, ...props}) => <a className="text-brand-400 hover:underline break-all" target="_blank" rel="noopener noreferrer" {...props} />,
                        code: ({node, inline, ...props}: any) => inline 
                          ? <code className="bg-gray-800 rounded px-1 py-0.5 font-mono text-[11px] text-brand-300" {...props} /> 
                          : <pre className="bg-gray-900 border border-gray-700 rounded p-2 my-2 overflow-x-auto"><code className="font-mono text-[11px] text-gray-300" {...props} /></pre>,
                        h1: ({node, ...props}) => <h1 className="text-lg font-bold mt-4 mb-2 text-white" {...props} />,
                        h2: ({node, ...props}) => <h2 className="text-md font-bold mt-3 mb-2 text-white" {...props} />,
                        h3: ({node, ...props}) => <h3 className="font-bold mt-2 mb-1 text-white" {...props} />
                      }}
                    >
                      {msg.content}
                    </ReactMarkdown>
                  </div>
                )}
              </div>
            </div>
          ))}

          {loading && (
            <div className="flex gap-3 animate-fade-in">
              <div className="bg-gray-800/60 rounded-xl rounded-bl-sm px-4 py-3 text-sm text-gray-400 flex flex-col gap-2 min-w-[280px]">
                <div className="flex items-center gap-2">
                  <Loader2 className="h-4 w-4 animate-spin text-brand-400" />
                  {runState.layer ? (
                    <>
                      <span className="font-mono text-xs text-gray-200">{runState.layer}</span>
                      <span className="text-[10px] text-gray-500">{runState.layerMessage}</span>
                    </>
                  ) : runState.llmModel ? (
                    <>
                      <span className="font-mono text-xs text-gray-200">{runState.llmModel}</span>
                      <span className="text-[10px] text-gray-500">
                        waiting on LLM…
                        {runState.llmStartedAt && (
                          <span className="ml-1 text-gray-600">
                            ({Math.round((Date.now() - runState.llmStartedAt) / 1000)}s)
                          </span>
                        )}
                      </span>
                    </>
                  ) : (
                    <>
                      <span>Agent running</span>
                      <span className="text-[10px] text-gray-600">• security pipeline active</span>
                    </>
                  )}
                  <Button
                    type="button"
                    onClick={handleCancel}
                    variant="outline"
                    size="sm"
                    className="ml-auto h-6 px-2 text-[10px] border-gray-700 text-gray-400 hover:text-red-300 hover:border-red-500/50"
                  >
                    <Square className="h-3 w-3 mr-1" />
                    Cancel
                  </Button>
                </div>
                {runState.runStartedAt && (
                  <div className="text-[10px] text-gray-600 font-mono">
                    Elapsed: {Math.round((Date.now() - runState.runStartedAt) / 1000)}s
                  </div>
                )}
                {stuck && (
                  <div className="flex items-center gap-2 text-[10px] text-amber-400 bg-amber-500/10 border border-amber-500/30 rounded px-2 py-1">
                    <AlertTriangle className="h-3 w-3" />
                    <span>
                      Sidecar may be stuck — no events for {Math.round((Date.now() - lastEventTsRef.current) / 1000)}s.
                      Cancel and retry?
                    </span>
                  </div>
                )}
              </div>
            </div>
          )}

          <div ref={chatEndRef} />
        </CardContent>

        {/* Input */}
        <div className="flex-none p-4 border-t border-gray-800/60">
          <form
            onSubmit={(e) => { e.preventDefault(); handleSend(); }}
            className="flex gap-2"
          >
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder={
                ollamaOnline
                  ? "Ask the agent to read files, query databases, send emails…"
                  : "Start Ollama to enable the agent"
              }
              disabled={!ollamaOnline || loading}
              className="flex-1 h-10 rounded-lg border border-gray-700 bg-gray-900 px-4 text-sm text-gray-200 placeholder:text-gray-600 focus:outline-none focus:ring-1 focus:ring-brand-500 disabled:opacity-50"
            />
            <Button type="submit" disabled={!ollamaOnline || loading || !input.trim()} className="h-10 px-4">
              <Send className="h-4 w-4" />
            </Button>
          </form>
        </div>
      </Card>
    </div>
  );
}
