import { useCallback, useEffect, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Filter,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Trash2,
  XCircle,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { apiFetch, getAgents, type RegisteredAgent } from "@/lib/api";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface SecurityEvent {
  id: number;
  timestamp: number; // unix float
  event_id: string;
  agent_id: string;
  layer: string;
  event_type: string;
  action: string;
  verdict: string;
  threat_level: string;
  message: string;
  details: string;
  tool_name: string;
  tool_args: string;
  latency_ms: number;
}

interface EventSummary {
  total: number;
  blocked: number;
  allowed: number;
  by_layer: Record<string, number>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function verdictColor(v: string) {
  switch (v?.toLowerCase()) {
    case "allow": return "text-emerald-400";
    case "deny":  return "text-red-400";
    case "warn":  return "text-yellow-400";
    default:      return "text-gray-400";
  }
}

function verdictIcon(v: string) {
  switch (v?.toLowerCase()) {
    case "allow": return <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />;
    case "deny":  return <ShieldX className="h-3.5 w-3.5 text-red-400" />;
    case "warn":  return <AlertTriangle className="h-3.5 w-3.5 text-yellow-400" />;
    default:      return <Shield className="h-3.5 w-3.5 text-gray-500" />;
  }
}

function threatBadge(level: string) {
  switch (level?.toLowerCase()) {
    case "critical": return <Badge className="bg-red-900/40 text-red-300 border-red-800 text-[10px]">CRITICAL</Badge>;
    case "high":     return <Badge className="bg-orange-900/40 text-orange-300 border-orange-800 text-[10px]">HIGH</Badge>;
    case "medium":   return <Badge className="bg-yellow-900/40 text-yellow-300 border-yellow-800 text-[10px]">MEDIUM</Badge>;
    case "low":      return <Badge className="bg-blue-900/40 text-blue-300 border-blue-800 text-[10px]">LOW</Badge>;
    default:         return null;
  }
}

function tsToTime(ts: number): string {
  if (!ts || ts < 1_000_000) return "—";
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function tsToDate(ts: number): string {
  if (!ts || ts < 1_000_000) return "";
  return new Date(ts * 1000).toLocaleDateString("en-US", { month: "short", day: "numeric" });
}

const LAYER_LABELS: Record<string, string> = {
  L1: "L1 Ingestion", L2: "L2 Storage", L3: "L3 Context",
  L4: "L4 Planning", L5: "L5 Execution", L6: "L6 Output",
  L7: "L7 Inter-Agent", L8: "L8 Identity",
};

// ---------------------------------------------------------------------------
// Event row component
// ---------------------------------------------------------------------------

function EventRow({ event }: { event: SecurityEvent }) {
  const [expanded, setExpanded] = useState(false);

  let parsedDetails: Record<string, unknown> = {};
  let parsedArgs: Record<string, unknown> = {};
  try { parsedDetails = JSON.parse(event.details || "{}"); } catch { /* */ }
  try { parsedArgs = JSON.parse(event.tool_args || "{}"); } catch { /* */ }

  const hasExtra = true; // Always allow expanding for full debug info

  return (
    <div
      className={cn(
        "border-b border-gray-800/50 transition-colors",
        event.verdict === "deny" ? "bg-red-950/10 hover:bg-red-950/20" : "hover:bg-gray-900/50",
      )}
    >
      {/* Main row */}
      <div
        className="flex items-center gap-3 px-4 py-2.5 cursor-pointer select-none"
        onClick={() => hasExtra && setExpanded((p) => !p)}
      >
        {/* Expand toggle */}
        <span className="text-gray-600 w-3 flex-none">
          {hasExtra ? (
            expanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />
          ) : null}
        </span>

        {/* Time */}
        <span className="text-[11px] font-mono text-gray-500 w-16 flex-none tabular-nums">
          {tsToTime(event.timestamp)}
        </span>

        {/* Layer badge */}
        <span className="flex-none">
          <Badge className="bg-gray-800 text-gray-300 border-gray-700 text-[10px] font-mono px-1.5">
            {LAYER_LABELS[event.layer] || event.layer || "—"}
          </Badge>
        </span>

        {/* Verdict icon */}
        <span className="flex-none">{verdictIcon(event.verdict)}</span>

        {/* Action */}
        <span className="font-mono text-[11px] text-gray-300 flex-1 truncate">
          {event.action || event.event_type || "—"}
        </span>

        {/* Agent */}
        <span className="text-[10px] text-gray-500 flex-none truncate max-w-[100px]">
          {event.agent_id}
        </span>

        {/* Threat */}
        <span className="flex-none">{threatBadge(event.threat_level)}</span>

        {/* Verdict label */}
        <span className={cn("text-[11px] font-semibold flex-none w-12 text-right", verdictColor(event.verdict))}>
          {event.verdict?.toUpperCase() || "—"}
        </span>
      </div>

      {/* Expanded detail panel */}
      {expanded && hasExtra && (
        <div className="px-10 pb-3 space-y-1.5">
          {event.message && (
            <p className="text-xs text-gray-400">{event.message}</p>
          )}
          {Object.keys(parsedArgs).length > 0 && (
            <div>
              <span className="text-[10px] text-gray-600 uppercase tracking-wide">Tool Args</span>
              <pre className="text-[10px] text-gray-400 bg-gray-900 rounded p-2 mt-0.5 overflow-x-auto">
                {JSON.stringify(parsedArgs, null, 2)}
              </pre>
            </div>
          )}
          {Object.keys(parsedDetails).length > 0 && (
            <div>
              <span className="text-[10px] text-gray-600 uppercase tracking-wide">Details</span>
              <pre className="text-[10px] text-gray-400 bg-gray-900 rounded p-2 mt-0.5 overflow-x-auto">
                {JSON.stringify(parsedDetails, null, 2)}
              </pre>
            </div>
          )}
          {event.latency_ms > 0 && (
            <p className="text-[10px] text-gray-600">
              Security overhead: <span className="font-mono text-gray-500">{Math.round(event.latency_ms)}ms</span>
            </p>
          )}
          <div className="pt-2 border-t border-gray-800/50 mt-2">
            <span className="text-[10px] text-gray-600 uppercase tracking-wide">Raw Event Data</span>
            <pre className="text-[10px] text-gray-500 bg-gray-950 rounded p-2 mt-0.5 overflow-x-auto border border-gray-800/50">
              {JSON.stringify(event, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Events page
// ---------------------------------------------------------------------------

export default function EventsPage() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [summary, setSummary] = useState<EventSummary | null>(null);
  const [agents, setAgents] = useState<RegisteredAgent[]>([]);
  const [loading, setLoading] = useState(false);

  // Filters
  const [agentFilter, setAgentFilter] = useState<string>("");
  const [layerFilter, setLayerFilter] = useState<string>("");
  const [verdictFilter, setVerdictFilter] = useState<string>("");
  const [search, setSearch] = useState<string>("");
  const [limit, setLimit] = useState(100);

  const fetchEvents = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ limit: String(limit) });
      if (agentFilter) params.append("agent_id", agentFilter);
      if (layerFilter) params.append("layer", layerFilter);
      if (verdictFilter) params.append("verdict", verdictFilter);

      const [eventsData, sumData, agentsData] = await Promise.all([
        apiFetch<{ events: SecurityEvent[] }>(`/events?${params}`),
        apiFetch<EventSummary>("/events/summary"),
        getAgents(),
      ]);
      setEvents(eventsData.events);
      setSummary(sumData);
      setAgents(agentsData.agents);
    } catch { /* sidecar offline */ }
    finally { setLoading(false); }
  }, [agentFilter, layerFilter, verdictFilter, limit]);

  useEffect(() => { fetchEvents(); }, [fetchEvents]);

  // Auto-refresh every 5s
  useEffect(() => {
    const id = setInterval(fetchEvents, 5_000);
    return () => clearInterval(id);
  }, [fetchEvents]);

  // Client-side search filter
  const filtered = search.trim()
    ? events.filter((e) =>
        e.action?.includes(search) ||
        e.agent_id?.includes(search) ||
        e.message?.includes(search) ||
        e.layer?.includes(search)
      )
    : events;

  const LAYERS = ["L1","L2","L3","L4","L5","L6","L7","L8"];

  return (
    <div className="flex flex-col gap-5 h-full min-h-0">
      {/* Header */}
      <div className="flex items-center justify-between flex-none">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            <Activity className="h-5 w-5 text-blue-400" />
            Security Events
          </h1>
          <p className="text-sm text-gray-500 mt-0.5">Real-time audit trail across all agents and security layers</p>
        </div>
        <Button
          size="sm"
          variant="outline"
          className="border-gray-700 text-gray-300 hover:bg-gray-800 gap-1.5"
          onClick={fetchEvents}
          disabled={loading}
        >
          <RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
          Refresh
        </Button>
      </div>

      {/* Summary cards */}
      {summary && (
        <div className="grid grid-cols-4 gap-3 flex-none">
          <Card className="bg-gray-900/60 border-gray-800">
            <CardContent className="p-3">
              <p className="text-[11px] text-gray-500 uppercase tracking-wide">Total</p>
              <p className="text-2xl font-bold text-white mt-0.5">{summary.total.toLocaleString()}</p>
            </CardContent>
          </Card>
          <Card className="bg-emerald-950/30 border-emerald-900/40">
            <CardContent className="p-3">
              <p className="text-[11px] text-emerald-600 uppercase tracking-wide">Allowed</p>
              <p className="text-2xl font-bold text-emerald-400 mt-0.5">{summary.allowed.toLocaleString()}</p>
            </CardContent>
          </Card>
          <Card className="bg-red-950/30 border-red-900/40">
            <CardContent className="p-3">
              <p className="text-[11px] text-red-600 uppercase tracking-wide">Blocked</p>
              <p className="text-2xl font-bold text-red-400 mt-0.5">{summary.blocked.toLocaleString()}</p>
            </CardContent>
          </Card>
          <Card className="bg-gray-900/60 border-gray-800">
            <CardContent className="p-3">
              <p className="text-[11px] text-gray-500 uppercase tracking-wide">Block Rate</p>
              <p className="text-2xl font-bold text-white mt-0.5">
                {summary.total > 0 ? Math.round((summary.blocked / summary.total) * 100) : 0}%
              </p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Layer breakdown pills */}
      {summary && Object.keys(summary.by_layer).length > 0 && (
        <div className="flex flex-wrap gap-2 flex-none">
          {LAYERS.filter((l) => summary.by_layer[l]).map((layer) => (
            <button
              key={layer}
              onClick={() => setLayerFilter(layerFilter === layer ? "" : layer)}
              className={cn(
                "inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-mono border transition-colors",
                layerFilter === layer
                  ? "bg-blue-900/50 border-blue-700 text-blue-300"
                  : "bg-gray-900 border-gray-700 text-gray-400 hover:border-gray-600",
              )}
            >
              {layer} <span className="font-sans font-semibold">{summary.by_layer[layer]}</span>
            </button>
          ))}
        </div>
      )}

      {/* Filters bar */}
      <div className="flex items-center gap-2 flex-none">
        {/* Search */}
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-500" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search actions, agents…"
            className="w-full pl-8 pr-3 py-1.5 text-sm bg-gray-900 border border-gray-700 rounded-md text-gray-300 placeholder-gray-600 focus:outline-none focus:border-gray-500"
          />
        </div>

        {/* Agent filter */}
        <select
          value={agentFilter}
          onChange={(e) => setAgentFilter(e.target.value)}
          className="px-2.5 py-1.5 text-sm bg-gray-900 border border-gray-700 rounded-md text-gray-300 focus:outline-none focus:border-gray-500"
        >
          <option value="">All Agents</option>
          {agents.map((a) => (
            <option key={a.agent_id} value={a.agent_id}>{a.agent_id}</option>
          ))}
        </select>

        {/* Layer filter */}
        <select
          value={layerFilter}
          onChange={(e) => setLayerFilter(e.target.value)}
          className="px-2.5 py-1.5 text-sm bg-gray-900 border border-gray-700 rounded-md text-gray-300 focus:outline-none focus:border-gray-500"
        >
          <option value="">All Layers</option>
          {LAYERS.map((l) => <option key={l} value={l}>{LAYER_LABELS[l]}</option>)}
        </select>

        {/* Verdict filter */}
        <select
          value={verdictFilter}
          onChange={(e) => setVerdictFilter(e.target.value)}
          className="px-2.5 py-1.5 text-sm bg-gray-900 border border-gray-700 rounded-md text-gray-300 focus:outline-none focus:border-gray-500"
        >
          <option value="">All Verdicts</option>
          <option value="allow">Allow</option>
          <option value="deny">Deny</option>
          <option value="warn">Warn</option>
        </select>

        {/* Limit */}
        <select
          value={limit}
          onChange={(e) => setLimit(Number(e.target.value))}
          className="px-2.5 py-1.5 text-sm bg-gray-900 border border-gray-700 rounded-md text-gray-300 focus:outline-none focus:border-gray-500"
        >
          <option value={50}>Last 50</option>
          <option value={100}>Last 100</option>
          <option value={250}>Last 250</option>
          <option value={500}>Last 500</option>
        </select>

        {/* Clear filters */}
        {(agentFilter || layerFilter || verdictFilter || search) && (
          <Button
            size="sm"
            variant="ghost"
            className="text-gray-500 hover:text-gray-300 gap-1"
            onClick={() => { setAgentFilter(""); setLayerFilter(""); setVerdictFilter(""); setSearch(""); }}
          >
            <XCircle className="h-3.5 w-3.5" />
            Clear
          </Button>
        )}

        <span className="text-[11px] text-gray-600 ml-auto">
          {filtered.length} event{filtered.length !== 1 ? "s" : ""}
        </span>
      </div>

      {/* Table */}
      <Card className="bg-gray-900/40 border-gray-800 flex-1 min-h-0 overflow-hidden flex flex-col">
        {/* Column headers */}
        <div className="flex items-center gap-3 px-4 py-2 border-b border-gray-800 bg-gray-900/60 flex-none">
          <span className="w-3 flex-none" />
          <span className="text-[10px] text-gray-600 uppercase tracking-wide w-16 flex-none">Time</span>
          <span className="text-[10px] text-gray-600 uppercase tracking-wide flex-none w-28">Layer</span>
          <span className="w-3.5 flex-none" />
          <span className="text-[10px] text-gray-600 uppercase tracking-wide flex-1">Action</span>
          <span className="text-[10px] text-gray-600 uppercase tracking-wide flex-none w-24">Agent</span>
          <span className="text-[10px] text-gray-600 uppercase tracking-wide flex-none w-16">Threat</span>
          <span className="text-[10px] text-gray-600 uppercase tracking-wide flex-none w-12 text-right">Verdict</span>
        </div>

        {/* Rows */}
        <div className="flex-1 overflow-y-auto">
          {loading && events.length === 0 ? (
            <div className="flex items-center justify-center h-32 text-gray-600 text-sm">Loading events…</div>
          ) : filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-48 gap-2 text-gray-600">
              <Shield className="h-8 w-8 text-gray-800" />
              <p className="text-sm">No events recorded yet</p>
              <p className="text-xs">Send a message in Agent Runner to generate security events</p>
            </div>
          ) : (
            [...filtered].reverse().map((e) => <EventRow key={e.id} event={e} />)
          )}
        </div>
      </Card>
    </div>
  );
}
