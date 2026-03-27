import { useEffect, useState } from "react";
import {
  Shield,
  Database,
  FileText,
  Brain,
  Play,
  Filter,
  Network,
  Fingerprint,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet";
import { cn } from "@/lib/utils";
import { getStatus, getLayers, getEvents, type StatusResponse, type LayersResponse, type SecurityEvent } from "@/lib/api";

// ---------------------------------------------------------------------------
// Layer metadata
// ---------------------------------------------------------------------------

const LAYERS = [
  { id: "L1", name: "Ingestion", key: "ingestion", icon: Shield },
  { id: "L2", name: "Storage", key: "storage", icon: Database },
  { id: "L3", name: "Context", key: "context", icon: FileText },
  { id: "L4", name: "Planning", key: "planning", icon: Brain },
  { id: "L5", name: "Execution", key: "execution", icon: Play },
  { id: "L6", name: "Output", key: "output", icon: Filter },
  { id: "L7", name: "Inter-Agent", key: "interagent", icon: Network },
  { id: "L8", name: "Identity", key: "identity", icon: Fingerprint },
] as const;

type LayerKey = (typeof LAYERS)[number]["key"];

interface LayerCard {
  id: string;
  name: string;
  key: LayerKey;
  icon: typeof Shield;
  enabled: boolean;
  blocked: number;
  status: "active" | "warning" | "error";
}

/** Count deny verdicts per layer from real event data. */
function countBlockedPerLayer(events: SecurityEvent[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const evt of events) {
    if (
      evt.type === "layer_result" &&
      (evt.verdict === "deny" || evt.verdict === "escalate")
    ) {
      const layer = String(evt.layer || "unknown");
      counts[layer] = (counts[layer] || 0) + 1;
    }
  }
  return counts;
}

function deriveCards(status: StatusResponse | null, blockedCounts: Record<string, number>): LayerCard[] {
  return LAYERS.map((l) => {
    const match = status?.layers.find(
      (sl) =>
        sl.name.toLowerCase().includes(l.key) ||
        sl.name.toLowerCase().includes(l.name.toLowerCase()),
    );
    const enabled = match?.enabled ?? false;
    // Use real blocked count from events — match layer key in event layer names
    const blocked = Object.entries(blockedCounts).reduce((sum, [layer, count]) => {
      if (layer.toLowerCase().includes(l.key)) return sum + count;
      return sum;
    }, 0);
    const layerStatus: LayerCard["status"] = !enabled
      ? "error"
      : blocked > 0
        ? "warning"
        : "active";
    return { ...l, icon: l.icon, enabled, blocked, status: layerStatus };
  });
}

const statusStyles: Record<LayerCard["status"], string> = {
  active:
    "border-emerald-500/20 bg-emerald-500/5 hover:border-emerald-500/40 hover:bg-emerald-500/10",
  warning:
    "border-amber-500/20 bg-amber-500/5 hover:border-amber-500/40 hover:bg-amber-500/10",
  error:
    "border-red-500/20 bg-red-500/5 hover:border-red-500/40 hover:bg-red-500/10",
};

const badgeVariant: Record<LayerCard["status"], "success" | "warning" | "destructive"> =
  { active: "success", warning: "warning", error: "destructive" };

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function LayerStatusGrid() {
  const [cards, setCards] = useState<LayerCard[]>(deriveCards(null, {}));
  const [layerConfigs, setLayerConfigs] = useState<LayersResponse | null>(null);
  const [selected, setSelected] = useState<LayerCard | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetch() {
      try {
        const [statusRes, layersRes, eventsRes] = await Promise.all([
          getStatus(),
          getLayers(),
          getEvents(500),
        ]);
        const blockedCounts = countBlockedPerLayer(eventsRes.events);
        setCards(deriveCards(statusRes, blockedCounts));
        setLayerConfigs(layersRes);
      } catch {
        setCards(deriveCards(null, {}));
      } finally {
        setLoading(false);
      }
    }
    fetch();
    const id = setInterval(fetch, 10_000);
    return () => clearInterval(id);
  }, []);

  const configForLayer = (key: LayerKey): Record<string, unknown> | null => {
    if (!layerConfigs) return null;
    return (layerConfigs as Record<string, Record<string, unknown>>)[key] ?? null;
  };

  return (
    <>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 h-full">
        {cards.map((card) => {
          const Icon = card.icon;
          return (
            <button
              key={card.id}
              onClick={() => setSelected(card)}
              className={cn(
                "rounded-xl border p-4 text-left transition-all duration-200 cursor-pointer group",
                statusStyles[card.status],
                loading && "animate-pulse",
              )}
            >
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <div
                    className={cn(
                      "h-8 w-8 rounded-lg flex items-center justify-center transition-colors",
                      card.status === "active" && "bg-emerald-500/20 text-emerald-400",
                      card.status === "warning" && "bg-amber-500/20 text-amber-400",
                      card.status === "error" && "bg-red-500/20 text-red-400",
                    )}
                  >
                    <Icon className="h-4 w-4" />
                  </div>
                  <span className="text-[10px] font-bold text-gray-500 tracking-widest">
                    {card.id}
                  </span>
                </div>
                <Badge variant={badgeVariant[card.status]}>
                  {card.status === "active"
                    ? "Active"
                    : card.status === "warning"
                      ? "Active"
                      : "Disabled"}
                </Badge>
              </div>
              <p className="text-sm font-medium text-gray-200 mb-1 group-hover:text-white transition-colors">
                {card.name}
              </p>
              <p className="text-xs text-gray-500">
                {card.blocked > 0 ? (
                  <>
                    <span className="text-amber-400 font-semibold">{card.blocked}</span>{" "}
                    blocked (24h)
                  </>
                ) : (
                  "No issues"
                )}
              </p>
            </button>
          );
        })}
      </div>

      {/* Slide-over config panel */}
      <Sheet open={!!selected} onOpenChange={(open) => !open && setSelected(null)}>
        <SheetContent side="right" className="overflow-y-auto">
          {selected && (
            <>
              <SheetHeader className="mb-6">
                <div className="flex items-center gap-3">
                  <div
                    className={cn(
                      "h-10 w-10 rounded-lg flex items-center justify-center",
                      selected.status === "active" && "bg-emerald-500/20 text-emerald-400",
                      selected.status === "warning" && "bg-amber-500/20 text-amber-400",
                      selected.status === "error" && "bg-red-500/20 text-red-400",
                    )}
                  >
                    <selected.icon className="h-5 w-5" />
                  </div>
                  <div>
                    <SheetTitle>
                      {selected.id} — {selected.name}
                    </SheetTitle>
                    <SheetDescription>Layer configuration details</SheetDescription>
                  </div>
                </div>
              </SheetHeader>

              <div className="space-y-4">
                <Card>
                  <CardHeader>
                    <CardTitle>Status</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-gray-400">State</span>
                      <Badge variant={badgeVariant[selected.status]}>
                        {selected.enabled ? "Enabled" : "Disabled"}
                      </Badge>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Blocked (24h)</span>
                      <span className="font-mono text-gray-200">{selected.blocked}</span>
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle>Configuration</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {configForLayer(selected.key) ? (
                      <pre className="text-xs text-gray-400 font-mono whitespace-pre-wrap leading-relaxed bg-gray-900 rounded-lg p-3 max-h-80 overflow-y-auto">
                        {JSON.stringify(configForLayer(selected.key), null, 2)}
                      </pre>
                    ) : (
                      <p className="text-xs text-gray-500">Loading…</p>
                    )}
                  </CardContent>
                </Card>
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>
    </>
  );
}
