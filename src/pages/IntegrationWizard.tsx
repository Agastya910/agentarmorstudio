import { useState } from "react";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { oneDark } from "react-syntax-highlighter/dist/esm/styles/prism";
import {
  ArrowLeft,
  ArrowRight,
  CheckCircle2,
  Clipboard,
  ClipboardCheck,
  ExternalLink,
  Link2,
  Play,
  RefreshCw,
  LayoutDashboard,
  Sparkles,
  ShieldCheck,
  Activity,
  Bot,
  Blocks,
  Code2,
  Server,
  Cpu,
  Network,
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { generateSnippet, type Framework, type IntegrationParts } from "@/lib/generateSnippet";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const STEPS = [
  { label: "Framework", description: "Choose your framework" },
  { label: "Layers", description: "Configure security layers" },
  { label: "Config", description: "Generated config" },
  { label: "Next steps", description: "You're all set" },
] as const;

interface FrameworkOption {
  id: Framework;
  name: string;
  description: string;
  icon: typeof Code2;
}

const FRAMEWORKS: FrameworkOption[] = [
  {
    id: "langchain",
    name: "LangChain",
    description: "Callback handler for LangChain agents",
    icon: Link2,
  },
  {
    id: "openai-agents",
    name: "OpenAI Agents SDK",
    description: "Tool wrapper for OpenAI function calling",
    icon: Bot,
  },
  {
    id: "mcp-server",
    name: "MCP Server",
    description: "Model Context Protocol integration",
    icon: Network,
  },
  {
    id: "custom-python",
    name: "Custom Python",
    description: "Basic wrap_tool() and intercept() usage",
    icon: Code2,
  },
  {
    id: "fastapi-proxy",
    name: "FastAPI Proxy",
    description: "Docker-based HTTP proxy with REST API",
    icon: Server,
  },
];

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

const RECOMMENDED = [1, 4, 6, 7, 8];
const MAXIMUM = [1, 2, 3, 4, 5, 6, 7, 8];

// ---------------------------------------------------------------------------
// Stepper component (inline)
// ---------------------------------------------------------------------------

function Stepper({ current }: { current: number }) {
  return (
    <div className="flex items-center gap-1 w-full max-w-xl mx-auto mb-8">
      {STEPS.map((step, i) => {
        const completed = i < current;
        const active = i === current;
        return (
          <div key={i} className="flex-1 flex items-center gap-1">
            <div className="flex flex-col items-center gap-1.5 flex-1">
              <div
                className={cn(
                  "h-9 w-9 rounded-full flex items-center justify-center text-xs font-bold transition-all",
                  completed
                    ? "bg-brand-600 text-white"
                    : active
                      ? "bg-brand-600/20 text-brand-400 ring-2 ring-brand-500/50"
                      : "bg-gray-800 text-gray-600",
                )}
              >
                {completed ? <CheckCircle2 className="h-4 w-4" /> : i + 1}
              </div>
              <span
                className={cn(
                  "text-[10px] font-medium text-center leading-tight",
                  active ? "text-brand-400" : completed ? "text-gray-300" : "text-gray-600",
                )}
              >
                {step.label}
              </span>
            </div>
            {i < STEPS.length - 1 && (
              <div
                className={cn(
                  "h-px flex-1 mb-5",
                  i < current ? "bg-brand-600" : "bg-gray-800",
                )}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function IntegrationWizard({
  onNavigate,
}: {
  onNavigate?: (page: string) => void;
}) {
  const [step, setStep] = useState(0);
  const [framework, setFramework] = useState<Framework | null>(null);
  const [enabledLayers, setEnabledLayers] = useState<Set<number>>(
    new Set(RECOMMENDED),
  );
  const [copiedPart, setCopiedPart] = useState<string | null>(null);

  const prev = () => setStep((s) => Math.max(0, s - 1));
  const next = () => setStep((s) => Math.min(STEPS.length - 1, s + 1));

  const toggleLayer = (id: number) => {
    setEnabledLayers((prev) => {
      const s = new Set(prev);
      s.has(id) ? s.delete(id) : s.add(id);
      return s;
    });
  };

  const applyPreset = (preset: number[]) => {
    setEnabledLayers(new Set(preset));
  };

  const snippetParts: IntegrationParts | null =
    framework && enabledLayers.size > 0
      ? generateSnippet(framework, Array.from(enabledLayers).sort())
      : null;

  const copySnippet = async (text: string, part: string) => {
    await navigator.clipboard.writeText(text);
    setCopiedPart(part);
    setTimeout(() => setCopiedPart(null), 2000);
  };

  const reset = () => {
    setStep(0);
    setFramework(null);
    setEnabledLayers(new Set(RECOMMENDED));
    setCopiedPart(null);
  };

  // ---------------------------------------------------------------------------
  // Step renderers
  // ---------------------------------------------------------------------------

  const renderStep1 = () => (
    <div className="space-y-4">
      <div className="text-center mb-6">
        <h2 className="text-lg font-semibold text-gray-100">Choose your framework</h2>
        <p className="text-xs text-gray-500 mt-1">
          Select the framework you use so we can generate the right integration code.
        </p>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 max-w-3xl mx-auto">
        {FRAMEWORKS.map((fw) => {
          const Icon = fw.icon;
          const selected = framework === fw.id;
          return (
            <button
              key={fw.id}
              onClick={() => setFramework(fw.id)}
              className={cn(
                "group rounded-xl border p-5 text-left transition-all duration-200",
                selected
                  ? "border-brand-500/60 bg-brand-600/10 ring-1 ring-brand-500/30"
                  : "border-gray-800 bg-gray-900/50 hover:border-gray-700 hover:bg-gray-800/50",
              )}
            >
              <div className="flex items-center gap-3 mb-2">
                <div
                  className={cn(
                    "h-9 w-9 rounded-lg flex items-center justify-center transition-colors",
                    selected
                      ? "bg-brand-600/20 text-brand-400"
                      : "bg-gray-800 text-gray-500 group-hover:text-gray-300",
                  )}
                >
                  <Icon className="h-4 w-4" />
                </div>
                {selected && (
                  <CheckCircle2 className="h-4 w-4 text-brand-400 ml-auto" />
                )}
              </div>
              <p className={cn(
                "text-sm font-medium",
                selected ? "text-brand-300" : "text-gray-200",
              )}>
                {fw.name}
              </p>
              <p className="text-[11px] text-gray-500 mt-0.5">{fw.description}</p>
            </button>
          );
        })}
      </div>
    </div>
  );

  const renderStep2 = () => (
    <div className="space-y-4 max-w-2xl mx-auto">
      <div className="text-center mb-6">
        <h2 className="text-lg font-semibold text-gray-100">Configure your layers</h2>
        <p className="text-xs text-gray-500 mt-1">
          Toggle the security layers you want to enable.
        </p>
      </div>

      {/* Preset buttons */}
      <div className="flex items-center justify-center gap-2 mb-4">
        <Button
          variant="outline"
          size="sm"
          onClick={() => applyPreset(RECOMMENDED)}
          className="text-xs gap-1.5"
        >
          <Sparkles className="h-3 w-3" />
          Recommended
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={() => applyPreset(MAXIMUM)}
          className="text-xs gap-1.5"
        >
          <ShieldCheck className="h-3 w-3" />
          Maximum Security
        </Button>
      </div>

      {/* Layer toggles */}
      <Card>
        <CardContent className="p-0 divide-y divide-gray-800/60">
          {LAYER_INFO.map((layer) => (
            <div
              key={layer.id}
              className="flex items-center justify-between px-5 py-3.5 hover:bg-gray-800/30 transition-colors"
            >
              <div className="flex items-center gap-3">
                <Badge
                  variant={enabledLayers.has(layer.id) ? "success" : "secondary"}
                  className="w-8 justify-center text-[10px] font-bold"
                >
                  L{layer.id}
                </Badge>
                <div>
                  <p className="text-sm font-medium text-gray-200">{layer.name}</p>
                  <p className="text-[11px] text-gray-500">{layer.desc}</p>
                </div>
              </div>
              <button
                type="button"
                role="switch"
                aria-checked={enabledLayers.has(layer.id)}
                onClick={() => toggleLayer(layer.id)}
                className={cn(
                  "relative inline-flex h-5 w-9 items-center rounded-full transition-colors flex-none",
                  enabledLayers.has(layer.id) ? "bg-brand-600" : "bg-gray-700",
                )}
              >
                <span
                  className={cn(
                    "inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform",
                    enabledLayers.has(layer.id)
                      ? "translate-x-[18px]"
                      : "translate-x-[3px]",
                  )}
                />
              </button>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );

  const renderStep3 = () => {
    if (!snippetParts) return null;

    const blocks = [
      {
        id: "yaml",
        title: "1. Create Configuration",
        filename: snippetParts.yaml.filename,
        code: snippetParts.yaml.code,
        lang: "yaml",
        desc: "Save this file in the root directory of your project.",
      },
      {
        id: "bash",
        title: "2. Install Dependencies",
        filename: "Terminal",
        code: snippetParts.bash.command,
        lang: "bash",
        desc: "Run this command to install the required AgentArmor packages.",
      },
      {
        id: "python",
        title: "3. Add Integration Code",
        filename: snippetParts.python.filename,
        code: snippetParts.python.code,
        lang: "python",
        desc: "Add this code to your agent script. It will automatically connect to this Studio.",
      },
    ];

    return (
      <div className="space-y-8 max-w-3xl mx-auto">
        <div className="text-center mb-6">
          <h2 className="text-lg font-semibold text-gray-100">Integration Instructions</h2>
          <p className="text-xs text-gray-500 mt-1">
            Follow these 3 steps to secure your{" "}
            <span className="text-gray-300 font-medium">
              {FRAMEWORKS.find((f) => f.id === framework)?.name}
            </span>{" "}
            agent.
          </p>
        </div>

        <div className="space-y-6">
          {blocks.map((block) => (
            <div key={block.id} className="space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-medium text-gray-200">{block.title}</h3>
                  <p className="text-[11px] text-gray-500">{block.desc}</p>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => copySnippet(block.code, block.id)}
                  className="text-xs gap-1.5 h-7 px-3 bg-gray-900/50"
                >
                  {copiedPart === block.id ? (
                    <><ClipboardCheck className="h-3 w-3 text-emerald-400" /> Copied!</>
                  ) : (
                    <><Clipboard className="h-3 w-3 text-gray-400" /> Copy</>
                  )}
                </Button>
              </div>
              
              <div className="rounded-xl overflow-hidden border border-gray-800 bg-[#0d1117] relative">
                <div className="absolute top-0 right-0 rounded-bl-lg bg-gray-800/80 px-2 py-1 border-b border-l border-gray-700">
                  <span className="text-[9px] font-mono text-gray-400">{block.filename}</span>
                </div>
                <SyntaxHighlighter
                  language={block.lang}
                  style={oneDark}
                  customStyle={{
                    margin: 0,
                    padding: "1.25rem",
                    paddingTop: "1.75rem",
                    fontSize: "12px",
                    lineHeight: "1.7",
                    background: "transparent",
                  }}
                  showLineNumbers
                  lineNumberStyle={{ color: "#3b4252", fontSize: "10px", paddingRight: "1rem" }}
                >
                  {block.code}
                </SyntaxHighlighter>
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  };

  const renderStep4 = () => (
    <div className="space-y-6 max-w-2xl mx-auto">
      <div className="text-center mb-6">
        <div className="inline-flex items-center justify-center h-14 w-14 rounded-full bg-emerald-500/10 text-emerald-400 mb-3">
          <CheckCircle2 className="h-7 w-7" />
        </div>
        <h2 className="text-lg font-semibold text-gray-100">You're all set!</h2>
        <p className="text-xs text-gray-500 mt-1">
          Here are some recommended next actions.
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        {/* Docs */}
        <a
          href="https://github.com/Agastya910/agentarmor"
          target="_blank"
          rel="noopener noreferrer"
          className="group rounded-xl border border-gray-800 bg-gray-900/50 p-5 hover:border-gray-700 hover:bg-gray-800/50 transition-all text-left"
        >
          <div className="h-9 w-9 rounded-lg bg-blue-500/10 text-blue-400 flex items-center justify-center mb-3">
            <ExternalLink className="h-4 w-4" />
          </div>
          <p className="text-sm font-medium text-gray-200">View Docs on GitHub</p>
          <p className="text-[11px] text-gray-500 mt-0.5">
            API reference &amp; advanced config
          </p>
        </a>

        {/* Agent Runner */}
        <button
          onClick={() => onNavigate?.("agent-runner")}
          className="group rounded-xl border border-gray-800 bg-gray-900/50 p-5 hover:border-gray-700 hover:bg-gray-800/50 transition-all text-left"
        >
          <div className="h-9 w-9 rounded-lg bg-amber-500/10 text-amber-400 flex items-center justify-center mb-3">
            <Play className="h-4 w-4" />
          </div>
          <p className="text-sm font-medium text-gray-200">Open Agent Runner</p>
          <p className="text-[11px] text-gray-500 mt-0.5">
            Test your integration live
          </p>
        </button>

        {/* Dashboard */}
        <button
          onClick={() => onNavigate?.("dashboard")}
          className="group rounded-xl border border-gray-800 bg-gray-900/50 p-5 hover:border-gray-700 hover:bg-gray-800/50 transition-all text-left"
        >
          <div className="h-9 w-9 rounded-lg bg-emerald-500/10 text-emerald-400 flex items-center justify-center mb-3">
            <Activity className="h-4 w-4" />
          </div>
          <p className="text-sm font-medium text-gray-200">Watch Security Events</p>
          <p className="text-[11px] text-gray-500 mt-0.5">
            Monitor the event feed in real time
          </p>
        </button>
      </div>

      <div className="flex justify-center pt-2">
        <Button variant="ghost" size="sm" onClick={reset} className="gap-1.5 text-xs text-gray-500">
          <RefreshCw className="h-3 w-3" />
          Start over
        </Button>
      </div>
    </div>
  );

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* Stepper */}
      <Stepper current={step} />

      {/* Step content */}
      <div className="flex-1 overflow-y-auto pb-4">
        {step === 0 && renderStep1()}
        {step === 1 && renderStep2()}
        {step === 2 && renderStep3()}
        {step === 3 && renderStep4()}
      </div>

      {/* Navigation */}
      {step < 3 && (
        <div className="flex items-center justify-between pt-4 border-t border-gray-800/60 flex-none">
          <Button
            variant="ghost"
            size="sm"
            onClick={prev}
            disabled={step === 0}
            className="gap-1.5 text-xs"
          >
            <ArrowLeft className="h-3 w-3" />
            Back
          </Button>
          <Button
            size="sm"
            onClick={next}
            disabled={step === 0 && !framework}
            className="gap-1.5 text-xs"
          >
            {step === 2 ? "Finish" : "Continue"}
            <ArrowRight className="h-3 w-3" />
          </Button>
        </div>
      )}
    </div>
  );
}
