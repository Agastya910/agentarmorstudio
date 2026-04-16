import { useState, useEffect } from "react";
import {
  Bot,
  CheckCircle2,
  ChevronRight,
  Globe,
  FileText,
  TerminalSquare,
  Play,
  Settings,
  Shield,
  Sparkles,
  Wrench,
  Loader2,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { apiFetch } from "@/lib/api";

// ---------------------------------------------------------------------------
// Constants & Types
// ---------------------------------------------------------------------------

const LAYER_INFO = [
  { id: 1, name: "Ingestion", desc: "Scans incoming prompts for injection attacks" },
  { id: 2, name: "Storage", desc: "Protects data at rest and memory access" },
  { id: 3, name: "Context", desc: "Guards RAG context and retrieval pipelines" },
  { id: 4, name: "Planning", desc: "Validates agent plans before execution" },
  { id: 5, name: "Execution", desc: "Sandboxes tool calls and system actions" },
  { id: 6, name: "Output", desc: "Redacts PII and sensitive data from responses" },
  { id: 7, name: "Inter-Agent", desc: "Secures agent-to-agent communication" },
  { id: 8, name: "Identity", desc: "Enforces authentication and access control" },
] as const;

const TOOLS = [
  { id: "web_search", name: "Web Search", desc: "Search Google/DuckDuckGo for live info", icon: Globe },
  { id: "file_read", name: "File Reader", desc: "Read local files from the workspace", icon: FileText },
  { id: "execute_command", name: "Command Runner", desc: "Execute safe shell commands", icon: TerminalSquare },
];

const PROVIDERS = [
  { id: "ollama", name: "Local Ollama", desc: "Runs completely locally, no API keys needed" },
  { id: "openai", name: "OpenAI API", desc: "Uses GPT-4o or gpt-3.5-turbo (requires OPENAI_API_KEY)" },
  { id: "anthropic", name: "Anthropic API", desc: "Uses Claude 3.5 Sonnet (requires ANTHROPIC_API_KEY)" },
];

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function Builder({ onNavigate }: { onNavigate?: (page: string) => void }) {
  const [name, setName] = useState("Ollama Researcher");
  const [systemPrompt, setSystemPrompt] = useState(
    "You are an expert researcher. Use your tools to find accurate information and answer the user's questions clearly.",
  );
  const [provider, setProvider] = useState("ollama");
  const [enabledLayers, setEnabledLayers] = useState<Set<number>>(new Set([1, 4, 5, 6]));
  const [enabledTools, setEnabledTools] = useState<Set<string>>(new Set(["web_search"]));
  const [providerApiKey, setProviderApiKey] = useState("");
  const [providerModel, setProviderModel] = useState("");
  const [ollamaModels, setOllamaModels] = useState<string[]>(["llama3.2"]);
  
  // Network Policy
  const [isolationLevel, setIsolationLevel] = useState("ALLOWLIST");
  const [domainAllowlist, setDomainAllowlist] = useState("");
  const [blockedDomains, setBlockedDomains] = useState("");
  
  const [isDeploying, setIsDeploying] = useState(false);

  useEffect(() => {
    if (provider === "ollama") {
      apiFetch<{models: {name: string}[]}>("/ollama/models")
        .then(data => {
            const models = data.models?.map(m => m.name) || ["llama3.2"];
            setOllamaModels(models);
            if (!providerModel || !models.includes(providerModel)) {
                setProviderModel(models[0]);
            }
        })
        .catch(err => console.error("Failed to fetch Ollama models:", err));
    } else {
        setProviderModel(""); // Clear model for APIs to use their defaults
    }
  }, [provider]);
  const [deploySuccess, setDeploySuccess] = useState(false);
  const [deployError, setDeployError] = useState("");

  const toggleLayer = (id: number) => {
    setEnabledLayers((prev) => {
      const s = new Set(prev);
      if (s.has(id)) s.delete(id);
      else s.add(id);
      return s;
    });
  };

  const toggleTool = (id: string) => {
    setEnabledTools((prev) => {
      const s = new Set(prev);
      if (s.has(id)) s.delete(id);
      else s.add(id);
      return s;
    });
  };

  const handleDeploy = async () => {
    if (!name.trim()) return;
    setIsDeploying(true);
    setDeploySuccess(false);
    setDeployError("");

    try {
      // Mock delay to feel substantial
      await new Promise(r => setTimeout(r, 600));
      
      const res = await apiFetch("/builder/deploy", {
        method: "POST",
        body: JSON.stringify({
          name: name.trim(),
          system_prompt: systemPrompt.trim(),
          provider,
          provider_model: providerModel,
          provider_api_key: providerApiKey.trim(),
          layers: Array.from(enabledLayers).sort(),
          tools: Array.from(enabledTools),
          isolation_level: isolationLevel,
          domain_allowlist: domainAllowlist.trim(),
          blocked_domains: blockedDomains.trim(),
        }),
      });

      setDeploySuccess(true);
      setTimeout(() => {
        onNavigate?.("agent-runner");
      }, 2000);
      
    } catch (err) {
      setDeployError(err instanceof Error ? err.message : "Unknown error occurred");
    } finally {
      setIsDeploying(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto space-y-6 pb-20">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-gray-100 flex items-center gap-2">
            <Sparkles className="h-6 w-6 text-brand-400" />
            Agent Builder
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Visually assemble and instantly deploy custom agents protected by AgentArmor.
          </p>
        </div>
        <Button
          onClick={handleDeploy}
          disabled={isDeploying || !name.trim()}
          className="gap-2 bg-brand-600 hover:bg-brand-500 text-white shadow-lg shadow-brand-500/20"
        >
          {isDeploying ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : deploySuccess ? (
            <CheckCircle2 className="h-4 w-4" />
          ) : (
            <Play className="h-4 w-4" />
          )}
          {isDeploying ? "Deploying..." : deploySuccess ? "Deployed!" : "Build & Deploy"}
        </Button>
      </div>

      {deployError && (
        <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
          {deployError}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Identity & Provider */}
        <div className="lg:col-span-1 space-y-6">
          <Card className="border-gray-800 bg-gray-900/50">
            <CardHeader className="pb-3 border-b border-gray-800/50">
              <CardTitle className="text-base flex items-center gap-2">
                <Settings className="h-4 w-4 text-brand-400" />
                Identity
              </CardTitle>
            </CardHeader>
            <CardContent className="pt-4 space-y-4">
              <div className="space-y-2">
                <label className="text-xs font-medium text-gray-300">Agent Name</label>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="w-full h-9 rounded-md border border-gray-700 bg-gray-950 px-3 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-brand-500"
                  placeholder="e.g. Finance Bot"
                />
              </div>
              <div className="space-y-2">
                <label className="text-xs font-medium text-gray-300">System Prompt</label>
                <textarea
                  value={systemPrompt}
                  onChange={(e) => setSystemPrompt(e.target.value)}
                  rows={4}
                  className="w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-brand-500 resize-none"
                  placeholder="Tell the agent how to behave..."
                />
              </div>
            </CardContent>
          </Card>

          <Card className="border-gray-800 bg-gray-900/50">
            <CardHeader className="pb-3 border-b border-gray-800/50">
              <CardTitle className="text-base flex items-center gap-2">
                <Bot className="h-4 w-4 text-purple-400" />
                LLM Provider
              </CardTitle>
            </CardHeader>
            <CardContent className="pt-4 space-y-2">
              {PROVIDERS.map((p) => (
                <button
                  key={p.id}
                  onClick={() => setProvider(p.id)}
                  className={cn(
                    "w-full text-left p-3 rounded-lg border transition-all",
                    provider === p.id
                      ? "border-purple-500/50 bg-purple-500/10"
                      : "border-gray-800 hover:border-gray-700 hover:bg-gray-800/50"
                  )}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className={cn(
                      "text-sm font-medium",
                      provider === p.id ? "text-purple-300" : "text-gray-200"
                    )}>
                      {p.name}
                    </span>
                    {provider === p.id && <CheckCircle2 className="h-4 w-4 text-purple-400" />}
                  </div>
                  <p className="text-[10px] text-gray-500 leading-tight block">{p.desc}</p>
                </button>
              ))}
              
              {provider === "ollama" ? (
                <div className="space-y-2 pt-3 mt-3 border-t border-gray-800/50 animate-in fade-in slide-in-from-top-2">
                  <label className="text-xs font-medium text-gray-300 flex justify-between">
                    Local Model
                  </label>
                  <select
                    value={providerModel}
                    onChange={(e) => setProviderModel(e.target.value)}
                    className="w-full h-9 rounded-md border border-gray-700 bg-gray-950 px-3 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-brand-500"
                  >
                    {ollamaModels.map(m => (
                      <option key={m} value={m}>{m}</option>
                    ))}
                  </select>
                </div>
              ) : (
                <div className="space-y-2 pt-3 mt-3 border-t border-gray-800/50 animate-in fade-in slide-in-from-top-2">
                  <label className="text-xs font-medium text-gray-300 flex justify-between">
                    API Key
                    <span className="text-brand-400 text-[10px]">Required</span>
                  </label>
                  <input
                    type="password"
                    value={providerApiKey}
                    onChange={(e) => setProviderApiKey(e.target.value)}
                    className="w-full h-9 rounded-md border border-gray-700 bg-gray-950 px-3 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-brand-500"
                    placeholder={`Enter ${provider === "openai" ? "OpenAI" : "Anthropic"} API Key`}
                  />
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Middle Column: Tools */}
        <div className="lg:col-span-1 space-y-6">
          <Card className="border-gray-800 bg-gray-900/50 h-full">
            <CardHeader className="pb-3 border-b border-gray-800/50">
              <CardTitle className="text-base flex items-center gap-2">
                <Wrench className="h-4 w-4 text-amber-400" />
                Capabilities
              </CardTitle>
              <CardDescription className="text-xs">
                Give your agent tools to interact with the world.
              </CardDescription>
            </CardHeader>
            <CardContent className="pt-4 space-y-3">
              {TOOLS.map((tool) => {
                const Icon = tool.icon;
                const isEnabled = enabledTools.has(tool.id);
                return (
                  <button
                    key={tool.id}
                    onClick={() => toggleTool(tool.id)}
                    className={cn(
                      "w-full text-left p-3 rounded-lg border transition-all flex items-start gap-3",
                      isEnabled
                        ? "border-amber-500/50 bg-amber-500/10"
                        : "border-gray-800 hover:border-gray-700 hover:bg-gray-800/50"
                    )}
                  >
                    <div className={cn(
                      "mt-0.5 p-1.5 rounded-md",
                      isEnabled ? "bg-amber-500/20 text-amber-400" : "bg-gray-800 text-gray-500"
                    )}>
                      <Icon className="h-4 w-4" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className={cn(
                          "text-sm font-medium",
                          isEnabled ? "text-amber-300" : "text-gray-200"
                        )}>
                          {tool.name}
                        </span>
                      </div>
                      <p className="text-[10px] text-gray-500 leading-tight block">{tool.desc}</p>
                    </div>
                  </button>
                );
              })}
            </CardContent>
          </Card>
        </div>

        {/* L5 Network Routing */}
        <div className="col-span-1 space-y-6">
          <Card className="border-gray-800 bg-gray-900/50 h-full">
            <CardHeader className="pb-3 border-b border-gray-800/50">
              <CardTitle className="text-base flex items-center gap-2">
                <Globe className="h-4 w-4 text-blue-400" />
                Network Routing
              </CardTitle>
              <CardDescription className="text-xs">
                Control agent network access.
              </CardDescription>
            </CardHeader>
            <CardContent className="pt-4 space-y-4">
              <div className="space-y-2">
                <label className="text-xs font-medium text-gray-300">Isolation Level</label>
                <select
                  value={isolationLevel}
                  onChange={(e) => setIsolationLevel(e.target.value)}
                  className="w-full h-9 rounded-md border border-gray-700 bg-gray-950 px-3 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-brand-500"
                >
                  <option value="ALLOWLIST">Allowlist Only (Recommended)</option>
                  <option value="OPEN">Open (All egress allowed)</option>
                  <option value="ISOLATED">Strictly Isolated</option>
                </select>
              </div>

              {isolationLevel === "ALLOWLIST" && (
                <div className="space-y-2 animate-in fade-in slide-in-from-top-2">
                  <label className="text-xs font-medium text-gray-300">Domain Allowlist</label>
                  <textarea
                    value={domainAllowlist}
                    onChange={(e) => setDomainAllowlist(e.target.value)}
                    rows={2}
                    className="w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-xs text-gray-200 focus:outline-none focus:ring-1 focus:ring-brand-500 resize-none font-mono"
                    placeholder="api.github.com, example.com"
                  />
                </div>
              )}
              
              {isolationLevel !== "ISOLATED" && (
                <div className="space-y-2 animate-in fade-in slide-in-from-top-2">
                  <label className="text-xs font-medium text-gray-300">Domain Blocklist</label>
                  <p className="text-[10px] text-gray-500 mt-0.5 leading-tight">
                    Overrides Allowlist. Internal IPs are blocked globally via L5 configuration.
                  </p>
                  <textarea
                    value={blockedDomains}
                    onChange={(e) => setBlockedDomains(e.target.value)}
                    rows={2}
                    className="w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-xs text-gray-200 focus:outline-none focus:ring-1 focus:ring-brand-500 resize-none font-mono"
                    placeholder="malicious.com"
                  />
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Right Column: Security Layers */}
        <div className="lg:col-span-1 space-y-6">
          <Card className="border-gray-800 bg-gray-900/50 h-full">
            <CardHeader className="pb-3 border-b border-gray-800/50">
              <CardTitle className="text-base flex items-center gap-2">
                <Shield className="h-4 w-4 text-emerald-400" />
                Security Layers
              </CardTitle>
              <CardDescription className="text-xs">
                Protect your agent with AgentArmor.
              </CardDescription>
            </CardHeader>
            <CardContent className="pt-4 space-y-2">
              {LAYER_INFO.map((layer) => {
                const isEnabled = enabledLayers.has(layer.id);
                return (
                  <div
                    key={layer.id}
                    className="flex justify-between items-center p-2 rounded-lg hover:bg-gray-800/40 transition-colors"
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-semibold text-gray-500">
                          L{layer.id}
                        </span>
                        <span className="text-sm font-medium text-gray-200">
                          {layer.name}
                        </span>
                      </div>
                      <p className="text-[10px] text-gray-500 ml-6">{layer.desc}</p>
                    </div>
                    <button
                      type="button"
                      role="switch"
                      aria-checked={isEnabled}
                      onClick={() => toggleLayer(layer.id)}
                      className={cn(
                        "relative inline-flex h-5 w-9 items-center rounded-full transition-colors flex-none",
                        isEnabled ? "bg-emerald-500" : "bg-gray-700"
                      )}
                    >
                      <span
                        className={cn(
                          "inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform",
                          isEnabled ? "translate-x-[18px]" : "translate-x-[3px]"
                        )}
                      />
                    </button>
                  </div>
                );
              })}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
