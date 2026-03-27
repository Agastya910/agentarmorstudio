import { useCallback, useEffect, useRef, useState } from "react";
import { Download, Search, SlidersHorizontal } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { getEvents, type SecurityEvent } from "@/lib/api";

// ---------------------------------------------------------------------------
// Layer color mapping
// ---------------------------------------------------------------------------

const LAYER_COLORS: Record<string, { bg: string; text: string; label: string }> = {
  identity_layer: { bg: "bg-violet-500/20", text: "text-violet-400", label: "L8" },
  ingestion_layer: { bg: "bg-blue-500/20", text: "text-blue-400", label: "L1" },
  storage_layer: { bg: "bg-cyan-500/20", text: "text-cyan-400", label: "L2" },
  context_layer: { bg: "bg-teal-500/20", text: "text-teal-400", label: "L3" },
  planning_layer: { bg: "bg-amber-500/20", text: "text-amber-400", label: "L4" },
  execution_layer: { bg: "bg-orange-500/20", text: "text-orange-400", label: "L5" },
  output_layer: { bg: "bg-pink-500/20", text: "text-pink-400", label: "L6" },
  interagent_layer: { bg: "bg-indigo-500/20", text: "text-indigo-400", label: "L7" },
  policy_engine: { bg: "bg-red-500/20", text: "text-red-400", label: "PE" },
};

function layerMeta(layer: string) {
  return (
    LAYER_COLORS[layer] ?? {
      bg: "bg-gray-700/30",
      text: "text-gray-400",
      label: layer.slice(0, 2).toUpperCase(),
    }
  );
}

const SEVERITY_OPTIONS = ["all", "low", "medium", "high", "critical"] as const;

// ---------------------------------------------------------------------------
// CSV export helper
// ---------------------------------------------------------------------------

function exportCSV(events: SecurityEvent[]) {
  const headers = ["timestamp", "event_id", "agent_id", "layer", "type", "action", "verdict"];
  const rows = events.map((e) =>
    headers.map((h) => String(e[h] ?? "")).join(","),
  );
  const csv = [headers.join(","), ...rows].join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `agentarmor_events_${Date.now()}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function EventFeed() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterLayer, setFilterLayer] = useState("all");
  const [filterSeverity, setFilterSeverity] = useState<string>("all");
  const [searchText, setSearchText] = useState("");
  const [showFilters, setShowFilters] = useState(false);
  const feedRef = useRef<HTMLDivElement>(null);

  // Poll events
  const fetchEvents = useCallback(async () => {
    try {
      const res = await getEvents(100);
      setEvents(res.events);
    } catch {
      /* sidecar not connected */
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchEvents();
    const id = setInterval(fetchEvents, 2000);
    return () => clearInterval(id);
  }, [fetchEvents]);

  // Derive unique layers for filter
  const uniqueLayers = ["all", ...new Set(events.map((e) => String(e.layer || "unknown")))];

  // Apply filters
  const filtered = events.filter((e) => {
    if (filterLayer !== "all" && String(e.layer) !== filterLayer) return false;
    if (
      filterSeverity !== "all" &&
      String(e.threat_level ?? e.verdict ?? "").toLowerCase() !== filterSeverity
    )
      return false;
    if (searchText) {
      const needle = searchText.toLowerCase();
      return (
        String(e.action ?? "").toLowerCase().includes(needle) ||
        String(e.agent_id ?? "").toLowerCase().includes(needle) ||
        String(e.event_id ?? "").toLowerCase().includes(needle)
      );
    }
    return true;
  });

  // Format timestamp
  function fmtTime(ts: unknown): string {
    if (!ts) return "—";
    const d = new Date(typeof ts === "number" ? ts * 1000 : String(ts));
    return d.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }

  return (
    <Card className="flex flex-col h-full">
      {/* Header + filters */}
      <CardHeader className="flex-none pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base">Security Event Feed</CardTitle>
          <div className="flex items-center gap-2">
            <span className="text-[10px] text-gray-500 tabular-nums mr-1">
              {filtered.length} event{filtered.length !== 1 ? "s" : ""}
            </span>
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setShowFilters((v) => !v)}
              className={cn(showFilters && "bg-gray-800")}
            >
              <SlidersHorizontal className="h-4 w-4" />
            </Button>
            <Button
              variant="ghost"
              size="icon"
              onClick={() => exportCSV(filtered)}
              title="Export CSV"
            >
              <Download className="h-4 w-4" />
            </Button>
          </div>
        </div>

        {/* Expandable filter bar */}
        {showFilters && (
          <div className="flex flex-wrap items-center gap-2 mt-3 animate-fade-in">
            {/* Search */}
            <div className="relative flex-1 min-w-[180px]">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-500" />
              <input
                type="text"
                placeholder="Filter events…"
                value={searchText}
                onChange={(e) => setSearchText(e.target.value)}
                className="w-full h-8 rounded-lg border border-gray-700 bg-gray-900 pl-8 pr-3 text-xs text-gray-200 placeholder:text-gray-600 focus:outline-none focus:ring-1 focus:ring-brand-500"
              />
            </div>

            {/* Layer filter */}
            <select
              value={filterLayer}
              onChange={(e) => setFilterLayer(e.target.value)}
              className="h-8 rounded-lg border border-gray-700 bg-gray-900 px-2 text-xs text-gray-200 focus:outline-none focus:ring-1 focus:ring-brand-500"
            >
              {uniqueLayers.map((l) => (
                <option key={l} value={l}>
                  {l === "all" ? "All Layers" : l}
                </option>
              ))}
            </select>

            {/* Severity filter */}
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="h-8 rounded-lg border border-gray-700 bg-gray-900 px-2 text-xs text-gray-200 focus:outline-none focus:ring-1 focus:ring-brand-500"
            >
              {SEVERITY_OPTIONS.map((s) => (
                <option key={s} value={s}>
                  {s === "all" ? "All Severity" : s.charAt(0).toUpperCase() + s.slice(1)}
                </option>
              ))}
            </select>
          </div>
        )}
      </CardHeader>

      {/* Event list */}
      <CardContent className="flex-1 overflow-hidden pt-0">
        <div
          ref={feedRef}
          className="h-full max-h-[400px] overflow-y-auto space-y-1 pr-1 scrollbar-thin"
        >
          {loading ? (
            <div className="flex items-center justify-center h-32">
              <div className="animate-spin h-6 w-6 border-2 border-brand-500 border-t-transparent rounded-full" />
            </div>
          ) : filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-32 text-gray-600 text-xs">
              <p>No security events recorded yet.</p>
              <p className="mt-1 text-gray-700">Events will appear here as they occur.</p>
            </div>
          ) : (
            filtered.map((evt, i) => {
              const meta = layerMeta(String(evt.layer || "unknown"));
              const verdict = String(evt.verdict ?? evt.type ?? "");
              return (
                <div
                  key={evt.event_id ?? i}
                  className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-gray-800/60 transition-colors group text-xs"
                >
                  {/* Timestamp */}
                  <span className="text-gray-600 font-mono w-16 flex-none tabular-nums">
                    {fmtTime(evt._timestamp ?? evt.timestamp)}
                  </span>

                  {/* Layer badge */}
                  <span
                    className={cn(
                      "flex-none w-8 text-center rounded px-1 py-0.5 text-[10px] font-bold",
                      meta.bg,
                      meta.text,
                    )}
                  >
                    {meta.label}
                  </span>

                  {/* Action / message */}
                  <span className="flex-1 text-gray-300 truncate">
                    {String(evt.action || evt.event_type || "—")}
                  </span>

                  {/* Agent */}
                  <span className="flex-none text-gray-500 truncate max-w-[80px]">
                    {evt.agent_id}
                  </span>

                  {/* Verdict */}
                  {verdict && (
                    <Badge
                      variant={
                        verdict === "deny"
                          ? "destructive"
                          : verdict === "allow"
                            ? "success"
                            : "secondary"
                      }
                      className="flex-none text-[10px] py-0"
                    >
                      {verdict}
                    </Badge>
                  )}
                </div>
              );
            })
          )}
        </div>
      </CardContent>
    </Card>
  );
}
