import { useEffect, useState } from "react";
import {
  LayoutDashboard,
  Shield,
  Activity,
  Settings,
  Play,
  Puzzle,
  ChevronLeft,
  ChevronRight,
  Wifi,
  WifiOff,
  Sparkles,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import SecurityScoreRing from "@/components/SecurityScoreRing";
import LayerStatusGrid from "@/components/LayerStatusGrid";
import EventFeed from "@/components/EventFeed";
import AgentRunner from "@/pages/AgentRunner";
import IntegrationWizard from "@/pages/IntegrationWizard";
import SettingsPage from "@/pages/Settings";
import Builder from "@/pages/Builder";
import EventsPage from "@/pages/Events";
import LayersPage from "@/pages/Layers";
import { getStatus } from "@/lib/api";

// ---------------------------------------------------------------------------
// Sidebar nav items
// ---------------------------------------------------------------------------

const NAV_ITEMS = [
  { icon: LayoutDashboard, label: "Dashboard", id: "dashboard" },
  { icon: Sparkles, label: "Agent Builder", id: "builder" },
  { icon: Play, label: "Agent Runner", id: "agent-runner" },
  { icon: Puzzle, label: "Integration", id: "integration" },
  { icon: Shield, label: "Layers", id: "layers" },
  { icon: Activity, label: "Events", id: "events" },
  { icon: Settings, label: "Settings", id: "settings" },
] as const;

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function Dashboard() {
  const [collapsed, setCollapsed] = useState(false);
  const [activeNav, setActiveNav] = useState("dashboard");
  const [connected, setConnected] = useState(false);
  const [now, setNow] = useState(new Date());

  // Connection health check
  useEffect(() => {
    async function check() {
      try {
        await getStatus();
        setConnected(true);
      } catch {
        setConnected(false);
      }
    }
    check();
    const id = setInterval(check, 5_000);
    return () => clearInterval(id);
  }, []);

  // Clock
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1_000);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="flex h-screen bg-gray-950 text-gray-100 font-sans overflow-hidden">
      {/* ── Sidebar ── */}
      <aside
        className={cn(
          "flex flex-col border-r border-gray-800/60 bg-gray-950 transition-all duration-300 ease-in-out flex-none",
          collapsed ? "w-16" : "w-56",
        )}
      >
        {/* Logo area */}
        <div className="flex items-center gap-2.5 px-4 h-14 border-b border-gray-800/60 flex-none">
          {!collapsed && (
            <span className="text-sm font-semibold tracking-tight truncate">
              AgentArmor
            </span>
          )}
        </div>

        {/* Nav items */}
        <nav className="flex-1 flex flex-col gap-1 px-2 py-3">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const active = activeNav === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveNav(item.id)}
                className={cn(
                  "flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors",
                  active
                    ? "bg-brand-600/15 text-brand-400"
                    : "text-gray-500 hover:bg-gray-800/60 hover:text-gray-300",
                  collapsed && "justify-center px-0",
                )}
                title={collapsed ? item.label : undefined}
              >
                <Icon className="h-4 w-4 flex-none" />
                {!collapsed && <span>{item.label}</span>}
              </button>
            );
          })}
        </nav>

        {/* Collapse toggle */}
        <div className="flex-none px-2 pb-3">
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setCollapsed((v) => !v)}
            className="w-full"
          >
            {collapsed ? (
              <ChevronRight className="h-4 w-4" />
            ) : (
              <ChevronLeft className="h-4 w-4" />
            )}
          </Button>
        </div>
      </aside>

      {/* ── Main area ── */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top bar */}
        <header className="flex items-center justify-between px-6 h-14 border-b border-gray-800/60 flex-none bg-gray-950/80 backdrop-blur-sm">
          <h1 className="text-base font-semibold tracking-tight">
            AgentArmor Studio
          </h1>
          <div className="flex items-center gap-4 text-xs">
            <div className="flex items-center gap-2">
              {connected ? (
                <>
                  <Wifi className="h-3.5 w-3.5 text-emerald-400" />
                  <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
                  <span className="text-emerald-400">Connected</span>
                </>
              ) : (
                <>
                  <WifiOff className="h-3.5 w-3.5 text-red-400" />
                  <span className="h-2 w-2 rounded-full bg-red-400" />
                  <span className="text-red-400">Disconnected</span>
                </>
              )}
            </div>
            <span className="text-gray-500 font-mono tabular-nums border-l border-gray-800 pl-4">
              {now.toLocaleTimeString("en-US", {
                hour12: false,
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
              })}
            </span>
          </div>
        </header>

        {/* Content area — all pages stay mounted to preserve state */}
        <main className="flex-1 overflow-y-auto p-6">
          <div className={activeNav === "builder" ? "h-full" : "hidden"}>
            <Builder onNavigate={setActiveNav} />
          </div>
          <div className={activeNav === "agent-runner" ? "h-full" : "hidden"}>
            <AgentRunner onNavigate={setActiveNav} />
          </div>
          <div className={activeNav === "integration" ? "h-full" : "hidden"}>
            <IntegrationWizard onNavigate={setActiveNav} />
          </div>
          <div className={activeNav === "dashboard" ? "h-full" : "hidden"}>
            <div className="grid grid-rows-[auto_1fr] gap-6 h-full min-h-0">
              {/* Top row: Score ring (1/3) + Layer grid (2/3) */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-1">
                  <SecurityScoreRing />
                </div>
                <div className="lg:col-span-2">
                  <LayerStatusGrid />
                </div>
              </div>

              {/* Bottom row: Event feed (full width) */}
              <div className="min-h-[320px]">
                <EventFeed />
              </div>
            </div>
          </div>
          <div className={activeNav === "settings" ? "h-full" : "hidden"}>
            <SettingsPage />
          </div>
          <div className={activeNav === "events" ? "h-full" : "hidden"}>
            <EventsPage />
          </div>
          <div className={activeNav === "layers" ? "h-full" : "hidden"}>
            <LayersPage />
          </div>
        </main>
      </div>
    </div>
  );
}
