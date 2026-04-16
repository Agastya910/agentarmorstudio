import { useEffect, useState } from "react";
import {
  ClipboardCheck,
  Clipboard,
  Eye,
  EyeOff,
  Key,
  Plus,
  RefreshCw,
  Shield,
  Trash2,
  UserPlus,
  Globe,
  Code,
  CheckCircle2,
  Lock,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import {
  getAgents,
  getApiKey,
  regenerateApiKey,
  registerAgent,
  unregisterAgent,
  apiFetch,
  type RegisteredAgent,
} from "@/lib/api";

// ---------------------------------------------------------------------------
// Framework options for registration
// ---------------------------------------------------------------------------

const FRAMEWORK_OPTIONS = [
  { value: "mcp", label: "MCP" },
  { value: "langchain", label: "LangChain" },
  { value: "openai", label: "OpenAI" },
  { value: "custom", label: "Custom" },
];

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

export default function SettingsPage() {
  const [apiKey, setApiKey] = useState("");
  const [keyFile, setKeyFile] = useState("");
  const [copied, setCopied] = useState(false);
  const [regenerating, setRegenerating] = useState(false);
  const [keyRevealed, setKeyRevealed] = useState(false);
  const [justGenerated, setJustGenerated] = useState(false);
  const [agents, setAgents] = useState<RegisteredAgent[]>([]);

  // External API keys
  const [tavilyKey, setTavilyKey] = useState("");
  const [e2bKey, setE2bKey] = useState("");
  const [tavilyConfigured, setTavilyConfigured] = useState(false);
  const [e2bConfigured, setE2bConfigured] = useState(false);
  const [savingApiKeys, setSavingApiKeys] = useState(false);
  const [apiKeySaved, setApiKeySaved] = useState(false);

  // Network Policy
  const [allowHttp, setAllowHttp] = useState(false);
  const [maxPayload, setMaxPayload] = useState("1024");
  const [savingPolicy, setSavingPolicy] = useState(false);
  const [policySaved, setPolicySaved] = useState(false);

  // Manual registration form
  const [agentName, setAgentName] = useState("");
  const [agentFramework, setAgentFramework] = useState("custom");
  const [registering, setRegistering] = useState(false);
  const [regMessage, setRegMessage] = useState("");

  // Load API key, agents, and external API key status
  useEffect(() => {
    const load = async () => {
      try {
        const keyResp = await getApiKey();
        setApiKey(keyResp.api_key);
        setKeyFile(keyResp.key_file || "");
      } catch { /* sidecar not available */ }
      try {
        const agentsResp = await getAgents();
        setAgents(agentsResp.agents);
      } catch { /* sidecar not available */ }
      try {
        const extResp = await apiFetch<{ tavily_configured: boolean; e2b_configured: boolean }>("/settings/external-apis");
        setTavilyConfigured(extResp.tavily_configured);
        setE2bConfigured(extResp.e2b_configured);
      } catch { /* sidecar not available */ }
      try {
        const polResp = await apiFetch<{ allow_http: boolean; max_payload: string }>("/settings/network-policy");
        setAllowHttp(polResp.allow_http);
        setMaxPayload(polResp.max_payload);
      } catch { /* */ }
    };
    load();
    const id = setInterval(load, 5_000);
    return () => clearInterval(id);
  }, []);

  const copyKey = async () => {
    await navigator.clipboard.writeText(apiKey);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleRegenerate = async () => {
    setRegenerating(true);
    try {
      const resp = await regenerateApiKey();
      setApiKey(resp.api_key);
      setKeyRevealed(true);
      setJustGenerated(true);
    } catch { /* */ }
    setRegenerating(false);
  };

  /** Mask the key: show first 6 and last 4 chars */
  const maskedKey = apiKey
    ? `${apiKey.slice(0, 6)}${"•".repeat(Math.max(0, apiKey.length - 10))}${apiKey.slice(-4)}`
    : "";

  const handleRegister = async () => {
    if (!agentName.trim()) return;
    setRegistering(true);
    setRegMessage("");
    try {
      await registerAgent(agentName.trim(), agentFramework, apiKey);
      setRegMessage(`✅ "${agentName}" registered! Check Agent Runner.`);
      setAgentName("");
      // Refresh agents list
      const agentsResp = await getAgents();
      setAgents(agentsResp.agents);
    } catch (err) {
      setRegMessage(`❌ Failed: ${err instanceof Error ? err.message : String(err)}`);
    }
    setRegistering(false);
  };

  const handleSaveApiKeys = async () => {
    setSavingApiKeys(true);
    setApiKeySaved(false);
    try {
      await apiFetch("/settings/external-apis", {
        method: "POST",
        body: JSON.stringify({ tavily_api_key: tavilyKey, e2b_api_key: e2bKey }),
      });
      const extResp = await apiFetch<{ tavily_configured: boolean; e2b_configured: boolean }>("/settings/external-apis");
      setTavilyConfigured(extResp.tavily_configured);
      setE2bConfigured(extResp.e2b_configured);
      setTavilyKey("");
      setE2bKey("");
      setApiKeySaved(true);
      setTimeout(() => setApiKeySaved(false), 3000);
    } catch { /* */ }
    setSavingApiKeys(false);
  };

  const handleSaveNetworkPolicy = async () => {
    setSavingPolicy(true);
    setPolicySaved(false);
    try {
      await apiFetch("/settings/network-policy", {
        method: "POST",
        body: JSON.stringify({ allow_http: allowHttp, max_payload: maxPayload }),
      });
      setPolicySaved(true);
      setTimeout(() => setPolicySaved(false), 3000);
    } catch { /* */ }
    setSavingPolicy(false);
  };

  const handleUnregister = async (agentId: string) => {
    try {
      await unregisterAgent(agentId, apiKey);
      const agentsResp = await getAgents();
      setAgents(agentsResp.agents);
    } catch { /* */ }
  };

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      {/* ── Studio API Key ── */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-sm">
            <Key className="h-4 w-4" />
            Studio API Key
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-xs text-gray-500">
            External agents need this key to register with Studio. Copy it and paste into your agent's config.
          </p>

          {/* Show-once banner after regeneration */}
          {justGenerated && (
            <div className="flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2">
              <span className="text-[11px] text-amber-400">
                ⚠️ Copy this key now — it won't be shown again in full.
              </span>
            </div>
          )}

          {/* Key display */}
          <div className="flex items-center gap-2">
            <div className="flex-1 bg-gray-900 border border-gray-800 rounded-lg px-4 py-2.5 font-mono text-xs tracking-wide overflow-x-auto">
              {apiKey
                ? <span className={keyRevealed ? "text-brand-400 select-all" : "text-gray-500"}>{keyRevealed ? apiKey : maskedKey}</span>
                : <span className="text-gray-600">Loading...</span>
              }
            </div>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setKeyRevealed(!keyRevealed)}
              className="h-8 w-8 p-0 flex-none text-gray-500 hover:text-gray-300"
              title={keyRevealed ? "Hide key" : "Reveal key"}
            >
              {keyRevealed ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
            </Button>
            <Button variant="outline" size="sm" onClick={copyKey} className="gap-1.5 flex-none">
              {copied ? (
                <><ClipboardCheck className="h-3 w-3 text-emerald-400" /> Copied</>
              ) : (
                <><Clipboard className="h-3 w-3" /> Copy</>
              )}
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleRegenerate}
              disabled={regenerating}
              className="gap-1.5 flex-none text-amber-400 border-amber-500/20 hover:bg-amber-500/10"
            >
              <RefreshCw className={cn("h-3 w-3", regenerating && "animate-spin")} />
              Regenerate
            </Button>
          </div>

          {keyFile && (
            <p className="text-[10px] text-gray-600">
              Stored at: <code className="text-gray-500">{keyFile}</code>
            </p>
          )}
        </CardContent>
      </Card>

      {/* ── External API Keys ── */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-sm">
            <Globe className="h-4 w-4 text-brand-400" />
            External API Keys
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-xs text-gray-500">
            Required for real tool execution. Keys are stored securely in{" "}
            <code className="text-gray-400">~/.agentarmor/studio.db</code>.
          </p>

          {/* Tavily */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <label className="text-xs font-medium text-gray-300 flex items-center gap-1.5">
                <Globe className="h-3 w-3 text-blue-400" />
                Tavily API Key
                <span className="text-[10px] text-gray-500">(web search — free at tavily.com)</span>
              </label>
              {tavilyConfigured && (
                <span className="flex items-center gap-1 text-[10px] text-emerald-400">
                  <CheckCircle2 className="h-3 w-3" /> Configured
                </span>
              )}
            </div>
            <input
              type="password"
              value={tavilyKey}
              onChange={(e) => setTavilyKey(e.target.value)}
              placeholder={tavilyConfigured ? "(already set — paste to update)" : "tvly-..."}
              className="w-full bg-gray-900 border border-gray-800 rounded-lg px-3 py-2 text-xs text-gray-200 placeholder-gray-600 focus:border-brand-500/50 focus:outline-none focus:ring-1 focus:ring-brand-500/20"
            />
          </div>

          {/* E2B */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <label className="text-xs font-medium text-gray-300 flex items-center gap-1.5">
                <Code className="h-3 w-3 text-purple-400" />
                E2B API Key
                <span className="text-[10px] text-gray-500">(code execution sandbox — e2b.dev)</span>
              </label>
              {e2bConfigured && (
                <span className="flex items-center gap-1 text-[10px] text-emerald-400">
                  <CheckCircle2 className="h-3 w-3" /> Configured
                </span>
              )}
            </div>
            <input
              type="password"
              value={e2bKey}
              onChange={(e) => setE2bKey(e.target.value)}
              placeholder={e2bConfigured ? "(already set — paste to update)" : "e2b_..."}
              className="w-full bg-gray-900 border border-gray-800 rounded-lg px-3 py-2 text-xs text-gray-200 placeholder-gray-600 focus:border-brand-500/50 focus:outline-none focus:ring-1 focus:ring-brand-500/20"
            />
          </div>

          <Button
            size="sm"
            onClick={handleSaveApiKeys}
            disabled={savingApiKeys || (!tavilyKey && !e2bKey)}
            className="gap-1.5"
          >
            {savingApiKeys ? (
              <RefreshCw className="h-3 w-3 animate-spin" />
            ) : apiKeySaved ? (
              <CheckCircle2 className="h-3 w-3 text-emerald-400" />
            ) : (
            )}
            {apiKeySaved ? "Saved!" : "Save Keys"}
          </Button>
        </CardContent>
      </Card>

      {/* ── L5 Network Policy ── */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-sm">
            <Lock className="h-4 w-4 text-emerald-400" />
            L5 Network Policy
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-xs text-gray-500">
            Global constraints for agent network execution. AgentArmor enforces these at the execution layer.
          </p>

          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <label className="text-xs font-medium text-gray-300">Require HTTPS Only</label>
                <p className="text-[10px] text-gray-500 mt-0.5">Block plaintext HTTP requests outbound.</p>
              </div>
              <button
                type="button"
                role="switch"
                aria-checked={!allowHttp}
                onClick={() => setAllowHttp(!allowHttp)}
                className={cn(
                  "relative inline-flex h-5 w-9 items-center rounded-full transition-colors flex-none",
                  !allowHttp ? "bg-emerald-500" : "bg-gray-700"
                )}
              >
                <span
                  className={cn(
                    "inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform",
                    !allowHttp ? "translate-x-[18px]" : "translate-x-[3px]"
                  )}
                />
              </button>
            </div>

            <div className="flex items-center justify-between">
              <div>
                <label className="text-xs font-medium text-gray-300">DNS Rebinding Protection</label>
                <p className="text-[10px] text-gray-500 mt-0.5">Always enforces resolution against 127.0.0.1 and known private blocks.</p>
              </div>
              <button
                type="button"
                role="switch"
                aria-checked={true}
                disabled
                className="relative inline-flex h-5 w-9 items-center rounded-full bg-emerald-500 opacity-50 cursor-not-allowed"
              >
                <span className="inline-block h-3.5 w-3.5 transform rounded-full bg-white translate-x-[18px]" />
              </button>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-medium text-gray-300">Max Outbound Payload (KB)</label>
              <input
                type="number"
                value={maxPayload}
                onChange={(e) => setMaxPayload(e.target.value)}
                placeholder="1024"
                className="w-full bg-gray-900 border border-gray-800 rounded-lg px-3 py-2 text-xs text-gray-200 focus:border-brand-500/50 focus:outline-none focus:ring-1 focus:ring-brand-500/20"
              />
            </div>
          </div>

          <Button
            size="sm"
            onClick={handleSaveNetworkPolicy}
            disabled={savingPolicy}
            className="gap-1.5"
          >
            {savingPolicy ? (
              <RefreshCw className="h-3 w-3 animate-spin" />
            ) : policySaved ? (
              <CheckCircle2 className="h-3 w-3 text-emerald-400" />
            ) : (
              <Lock className="h-3 w-3" />
            )}
            {policySaved ? "Saved!" : "Save Policy"}
          </Button>
        </CardContent>
      </Card>

      {/* ── Manual Agent Registration ── */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-sm">
            <UserPlus className="h-4 w-4" />
            Register Agent Manually
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-xs text-gray-500">
            Register an agent directly from the Studio. It will appear in the Agent Runner immediately.
            For developers, integration snippets include auto-registration code.
          </p>

          <div className="flex items-end gap-3">
            {/* Agent Name */}
            <div className="flex-1">
              <label className="text-[10px] text-gray-500 font-medium uppercase tracking-wider mb-1.5 block">
                Agent Name
              </label>
              <input
                type="text"
                value={agentName}
                onChange={(e) => setAgentName(e.target.value)}
                placeholder="e.g. my-langchain-bot"
                className="w-full bg-gray-900 border border-gray-800 rounded-lg px-3 py-2 text-xs text-gray-200 placeholder-gray-600 focus:border-brand-500/50 focus:outline-none focus:ring-1 focus:ring-brand-500/20"
              />
            </div>

            {/* Framework */}
            <div className="w-36">
              <label className="text-[10px] text-gray-500 font-medium uppercase tracking-wider mb-1.5 block">
                Framework
              </label>
              <select
                value={agentFramework}
                onChange={(e) => setAgentFramework(e.target.value)}
                className="w-full bg-gray-900 border border-gray-800 rounded-lg px-3 py-2 text-xs text-gray-200 focus:border-brand-500/50 focus:outline-none focus:ring-1 focus:ring-brand-500/20 appearance-none"
              >
                {FRAMEWORK_OPTIONS.map((fw) => (
                  <option key={fw.value} value={fw.value}>{fw.label}</option>
                ))}
              </select>
            </div>

            {/* Register button */}
            <Button
              size="sm"
              onClick={handleRegister}
              disabled={registering || !agentName.trim()}
              className="gap-1.5 flex-none"
            >
              {registering ? (
                <RefreshCw className="h-3 w-3 animate-spin" />
              ) : (
                <Plus className="h-3 w-3" />
              )}
              Register
            </Button>
          </div>

          {regMessage && (
            <p className={cn(
              "text-xs",
              regMessage.startsWith("✅") ? "text-emerald-400" : "text-red-400",
            )}>
              {regMessage}
            </p>
          )}
        </CardContent>
      </Card>

      {/* ── Connected Agents ── */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-sm">
            <Shield className="h-4 w-4" />
            Connected Agents
            <Badge variant="secondary" className="ml-auto text-[9px]">
              {agents.length}
            </Badge>
          </CardTitle>
        </CardHeader>
        <CardContent>
          {agents.length === 0 ? (
            <p className="text-xs text-gray-600 text-center py-4">No agents connected.</p>
          ) : (
            <div className="space-y-2">
              {agents.map((agent) => (
                <div
                  key={agent.agent_id}
                  className="flex items-center gap-3 rounded-lg border border-gray-800 bg-gray-900/50 px-4 py-3"
                >
                  <div className={cn(
                    "h-2 w-2 rounded-full flex-none",
                    agent.status === "online" ? "bg-emerald-400 animate-pulse" : "bg-gray-600",
                  )} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-medium text-gray-200">{agent.agent_id}</span>
                      <Badge className={cn("text-[9px] px-1.5 py-0 border", frameworkColor(agent.framework))}>
                        {agent.framework}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-3 mt-0.5">
                      <span className="text-[10px] text-gray-500">
                        {agent.events_count} event{agent.events_count !== 1 ? "s" : ""}
                      </span>
                      {agent.blocked_count > 0 && (
                        <span className="text-[10px] text-red-400">{agent.blocked_count} blocked</span>
                      )}
                      <span className={cn(
                        "text-[10px]",
                        agent.status === "online" ? "text-emerald-500" : "text-gray-600",
                      )}>
                        {agent.status}
                      </span>
                    </div>
                  </div>
                  {agent.agent_id !== "studio" && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleUnregister(agent.agent_id)}
                      className="text-gray-600 hover:text-red-400 h-7 w-7 p-0"
                    >
                      <Trash2 className="h-3 w-3" />
                    </Button>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
