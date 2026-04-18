import { useState, useEffect } from "react";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  ChevronDown,
  ChevronRight,
  Zap,
  Lock,
  Brain,
  FileSearch,
  Cpu,
  Eye,
  Users,
  Fingerprint,
  Loader2,
  AlertTriangle,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { apiFetch, type LayersResponse } from "@/lib/api";

// ---------------------------------------------------------------------------
// Layer metadata
// ---------------------------------------------------------------------------

const LAYER_META = [
  {
    id: "ingestion",
    num: 1,
    name: "L1 — Ingestion",
    subtitle: "Input Scanning & Prompt Injection Detection",
    icon: Zap,
    color: "text-rose-400",
    bg: "bg-rose-500/10",
    border: "border-rose-500/30",
    desc: "Scans all incoming prompts through Unicode normalization, regex pattern matching, and ML-based classification (Prompt Guard) to detect prompt injection, jailbreak attempts, and adversarial inputs before they reach the LLM.",
    capabilities: [
      "Unicode homoglyph normalization & invisible character stripping",
      "Multi-category regex pattern matching (role hijack, system override, data exfil, social engineering)",
      "Prompt Guard 2 ML classifier (INJECTION / JAILBREAK / BENIGN)",
      "Content Disarm & Reconstruction (CDR) for HTML inputs",
      "Severity-weighted threat scoring with configurable thresholds",
    ],
  },
  {
    id: "storage",
    num: 2,
    name: "L2 — Storage",
    subtitle: "Data-at-Rest Encryption & Tamper Detection",
    icon: Lock,
    color: "text-amber-400",
    bg: "bg-amber-500/10",
    border: "border-amber-500/30",
    desc: "Protects all persisted data (conversations, API keys, security events) with AES-256-GCM encryption and HMAC-SHA256 integrity verification. Prevents memory poisoning attacks by detecting any unauthorized modifications to stored data.",
    capabilities: [
      "AES-256-GCM field-level encryption with unique nonces",
      "HMAC-SHA256 row-level integrity MAC verification",
      "Machine-bound master key derivation (install.salt + PBKDF2)",
      "Automatic tamper detection on conversation history reads",
      "Sub-millisecond encryption/decryption latency budget",
    ],
  },
  {
    id: "context",
    num: 3,
    name: "L3 — Context",
    subtitle: "RAG Pipeline Protection & Retrieval Guarding",
    icon: Brain,
    color: "text-purple-400",
    bg: "bg-purple-500/10",
    border: "border-purple-500/30",
    desc: "Guards the context assembly pipeline against structural template injection and semantic hijacking. Applies tiered data-marking, multi-canary token injection, and goal-drift detection to prevent adversarial content from influencing the LLM's behavior.",
    capabilities: [
      "Structural template injection stripping",
      "Tiered data-marking (verified / medium / low trust)",
      "Multi-canary token injection for exfiltration detection",
      "Goal-drift detection via semantic similarity scoring",
      "Tool output re-scanning before context insertion",
    ],
  },
  {
    id: "planning",
    num: 4,
    name: "L4 — Planning",
    subtitle: "Action Plan Validation & Risk Assessment",
    icon: FileSearch,
    color: "text-blue-400",
    bg: "bg-blue-500/10",
    border: "border-blue-500/30",
    desc: "Validates agent action plans before execution by analyzing verb-risk levels, resource sensitivity, and multi-step chain escalation patterns. Prevents privilege escalation through seemingly innocent sequential operations.",
    capabilities: [
      "Verb-risk classification (read/write/delete/execute/admin)",
      "Resource sensitivity scoring (public → confidential → critical)",
      "Chain escalation detection across multi-step plans",
      "Compound risk assessment for action sequences",
      "Automatic plan rejection above configurable risk thresholds",
    ],
  },
  {
    id: "execution",
    num: 5,
    name: "L5 — Execution",
    subtitle: "Tool Sandboxing & Network Policy Enforcement",
    icon: Cpu,
    color: "text-cyan-400",
    bg: "bg-cyan-500/10",
    border: "border-cyan-500/30",
    desc: "Sandboxes all tool calls within strict security boundaries. Enforces network policies (allowlist/blocklist/isolation), blocks SSRF attacks against internal services, and validates all file operations within workspace boundaries.",
    capabilities: [
      "Network isolation modes (ALLOWLIST / OPEN / ISOLATED)",
      "SSRF protection: blocks 169.254.x.x, 10.x.x.x, 127.x.x.x, etc.",
      "Cloud metadata service blocking (AWS, GCP, Azure IMDSv2)",
      "Path traversal prevention for all file I/O",
      "Per-agent workspace sandboxing (~/.agentarmor/agents/<id>/workspace/)",
    ],
  },
  {
    id: "output",
    num: 6,
    name: "L6 — Output",
    subtitle: "PII Redaction & Credential Scanning",
    icon: Eye,
    color: "text-emerald-400",
    bg: "bg-emerald-500/10",
    border: "border-emerald-500/30",
    desc: "Scans all LLM responses through a 5-scanner pipeline before they reach the user. Detects and redacts PII (names, emails, SSNs, phone numbers), leaked credentials (API keys, tokens), and harmful content.",
    capabilities: [
      "Credential pattern scanning (AWS keys, GitHub tokens, API secrets)",
      "PII detection via Presidio NLP engine (15+ entity types)",
      "Harmful content keyword detection",
      "Semantic exfiltration detection (encoded data patterns)",
      "Automatic redaction with configurable replacement tokens",
    ],
  },
  {
    id: "interagent",
    num: 7,
    name: "L7 — Inter-Agent",
    subtitle: "Agent-to-Agent Communication Security",
    icon: Users,
    color: "text-indigo-400",
    bg: "bg-indigo-500/10",
    border: "border-indigo-500/30",
    desc: "Secures communication between agents in multi-agent systems. Prevents replay attacks, enforces delegation certificates, tracks directed-pair trust scores, and detects behavioral anomalies in inter-agent messaging patterns.",
    capabilities: [
      "Replay prevention via nonce/timestamp registry",
      "Delegation certificate authorization chains",
      "Directed-pair trust scoring with hourly decay",
      "Scope binding validation for delegated tasks",
      "Behavioral anomaly detection (frequency, payload size, entropy)",
    ],
  },
  {
    id: "identity",
    num: 8,
    name: "L8 — Identity",
    subtitle: "Authentication & Access Control",
    icon: Fingerprint,
    color: "text-pink-400",
    bg: "bg-pink-500/10",
    border: "border-pink-500/30",
    desc: "Enforces identity verification and role-based access control for all agent operations. Validates API keys, tracks session integrity, and ensures agents operate within their authorized scope.",
    capabilities: [
      "API key validation and session binding",
      "Role-based access control (RBAC) enforcement",
      "Agent identity attestation",
      "Permission boundary enforcement",
      "Audit logging for all authorization decisions",
    ],
  },
];

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function Layers() {
  const [layerData, setLayerData] = useState<LayersResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [expandedLayers, setExpandedLayers] = useState<Set<string>>(new Set());

  useEffect(() => {
    apiFetch<LayersResponse>("/layers")
      .then((data) => {
        setLayerData(data);
        setError("");
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load layers"))
      .finally(() => setLoading(false));
  }, []);

  const toggleExpand = (id: string) => {
    setExpandedLayers((prev) => {
      const s = new Set(prev);
      if (s.has(id)) s.delete(id);
      else s.add(id);
      return s;
    });
  };

  const expandAll = () => {
    if (expandedLayers.size === LAYER_META.length) {
      setExpandedLayers(new Set());
    } else {
      setExpandedLayers(new Set(LAYER_META.map((l) => l.id)));
    }
  };

  const getLayerEnabled = (id: string): boolean => {
    if (!layerData) return false;
    const config = (layerData as Record<string, any>)[id];
    return config?.enabled !== false;
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <Loader2 className="h-8 w-8 animate-spin text-brand-400" />
      </div>
    );
  }

  const enabledCount = LAYER_META.filter((l) => getLayerEnabled(l.id)).length;

  return (
    <div className="max-w-5xl mx-auto space-y-6 pb-20">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-gray-100 flex items-center gap-2">
            <Shield className="h-6 w-6 text-brand-400" />
            Security Layers
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            8-layer defense-in-depth architecture protecting your agents at every stage.
          </p>
        </div>
        <button
          onClick={expandAll}
          className="text-xs text-gray-500 hover:text-gray-300 transition-colors px-3 py-1.5 rounded-md border border-gray-800 hover:border-gray-700"
        >
          {expandedLayers.size === LAYER_META.length ? "Collapse All" : "Expand All"}
        </button>
      </div>

      {/* Summary bar */}
      <div className="flex items-center gap-4 p-4 rounded-xl border border-gray-800 bg-gray-900/50">
        <div className="flex items-center gap-3">
          <div className="relative">
            <svg className="h-14 w-14 -rotate-90" viewBox="0 0 36 36">
              <circle
                cx="18" cy="18" r="14"
                fill="none"
                stroke="currentColor"
                strokeWidth="3"
                className="text-gray-800"
              />
              <circle
                cx="18" cy="18" r="14"
                fill="none"
                stroke="currentColor"
                strokeWidth="3"
                strokeDasharray={`${(enabledCount / 8) * 88} 88`}
                strokeLinecap="round"
                className="text-emerald-400 transition-all duration-700"
              />
            </svg>
            <span className="absolute inset-0 flex items-center justify-center text-sm font-bold text-gray-100">
              {enabledCount}/8
            </span>
          </div>
          <div>
            <p className="text-sm font-medium text-gray-200">
              {enabledCount === 8
                ? "Full Protection Active"
                : `${enabledCount} of 8 Layers Active`}
            </p>
            <p className="text-xs text-gray-500">
              {enabledCount === 8
                ? "All defense layers are operational"
                : `${8 - enabledCount} layer${8 - enabledCount > 1 ? "s" : ""} disabled — consider enabling for complete coverage`}
            </p>
          </div>
        </div>

        {enabledCount < 8 && (
          <div className="ml-auto flex items-center gap-2 text-amber-400">
            <AlertTriangle className="h-4 w-4" />
            <span className="text-xs font-medium">Partial Coverage</span>
          </div>
        )}
      </div>

      {error && (
        <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
          {error}
        </div>
      )}

      {/* Layer cards */}
      <div className="space-y-3">
        {LAYER_META.map((layer) => {
          const Icon = layer.icon;
          const enabled = getLayerEnabled(layer.id);
          const expanded = expandedLayers.has(layer.id);

          return (
            <Card
              key={layer.id}
              className={cn(
                "border transition-all duration-200 cursor-pointer",
                enabled
                  ? `${layer.border} bg-gray-900/50 hover:bg-gray-900/70`
                  : "border-gray-800/50 bg-gray-950/50 opacity-60 hover:opacity-80"
              )}
              onClick={() => toggleExpand(layer.id)}
            >
              <CardHeader className="py-4 px-5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    {/* Layer number badge */}
                    <div
                      className={cn(
                        "flex items-center justify-center h-10 w-10 rounded-lg",
                        enabled ? layer.bg : "bg-gray-800/50"
                      )}
                    >
                      <Icon
                        className={cn(
                          "h-5 w-5",
                          enabled ? layer.color : "text-gray-600"
                        )}
                      />
                    </div>

                    <div>
                      <CardTitle className="text-sm font-semibold flex items-center gap-2">
                        <span className={enabled ? "text-gray-100" : "text-gray-500"}>
                          {layer.name}
                        </span>
                      </CardTitle>
                      <p className="text-xs text-gray-500 mt-0.5">{layer.subtitle}</p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    {/* Status badge */}
                    <div
                      className={cn(
                        "flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-semibold uppercase tracking-wider",
                        enabled
                          ? "bg-emerald-500/15 text-emerald-400"
                          : "bg-gray-800 text-gray-500"
                      )}
                    >
                      {enabled ? (
                        <ShieldCheck className="h-3 w-3" />
                      ) : (
                        <ShieldAlert className="h-3 w-3" />
                      )}
                      {enabled ? "Active" : "Disabled"}
                    </div>

                    {/* Expand chevron */}
                    {expanded ? (
                      <ChevronDown className="h-4 w-4 text-gray-500" />
                    ) : (
                      <ChevronRight className="h-4 w-4 text-gray-500" />
                    )}
                  </div>
                </div>
              </CardHeader>

              {expanded && (
                <CardContent className="pt-0 pb-5 px-5 border-t border-gray-800/50">
                  <div className="ml-14 space-y-4 mt-3">
                    <p className="text-sm text-gray-400 leading-relaxed">
                      {layer.desc}
                    </p>

                    <div>
                      <h4 className="text-xs font-semibold text-gray-300 uppercase tracking-wider mb-2">
                        Capabilities
                      </h4>
                      <ul className="space-y-1.5">
                        {layer.capabilities.map((cap, i) => (
                          <li
                            key={i}
                            className="flex items-start gap-2 text-xs text-gray-400"
                          >
                            <span
                              className={cn(
                                "mt-1.5 h-1.5 w-1.5 rounded-full flex-none",
                                enabled ? layer.color.replace("text-", "bg-") : "bg-gray-700"
                              )}
                            />
                            {cap}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </CardContent>
              )}
            </Card>
          );
        })}
      </div>
    </div>
  );
}
