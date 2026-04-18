import { useEffect, useState } from "react";
import { Download, RefreshCw, X } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface UpdateInfo {
  version: string;
  date?: string;
  body?: string;
}

type UpdateState =
  | { phase: "idle" }
  | { phase: "available"; info: UpdateInfo }
  | { phase: "downloading"; progress: number; total: number }
  | { phase: "ready" }
  | { phase: "error"; message: string };

/** Detect whether we're running inside a Tauri webview. */
function isTauri(): boolean {
  return typeof window !== "undefined" && !!(window as any).__TAURI_INTERNALS__;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function UpdateNotification() {
  const [state, setState] = useState<UpdateState>({ phase: "idle" });
  const [dismissed, setDismissed] = useState(false);

  // Check for updates on mount (only inside Tauri)
  useEffect(() => {
    if (!isTauri()) return;
    let cancelled = false;

    async function checkForUpdate() {
      try {
        const { check } = await import("@tauri-apps/plugin-updater");
        const update = await check();
        if (!cancelled && update?.available) {
          setState({
            phase: "available",
            info: {
              version: update.version,
              date: update.date ?? undefined,
              body: update.body ?? undefined,
            },
          });
        }
      } catch (err) {
        // Silently ignore update check failures (offline, etc.)
        console.warn("[Updater] Check failed:", err);
      }
    }

    checkForUpdate();
    return () => {
      cancelled = true;
    };
  }, []);

  // Download and install
  const handleUpdate = async () => {
    try {
      const { check } = await import("@tauri-apps/plugin-updater");
      const update = await check();
      if (!update?.available) return;

      setState({ phase: "downloading", progress: 0, total: 0 });

      let downloaded = 0;
      let contentLength = 0;

      await update.downloadAndInstall((event) => {
        switch (event.event) {
          case "Started":
            contentLength = event.data.contentLength ?? 0;
            setState({ phase: "downloading", progress: 0, total: contentLength });
            break;
          case "Progress":
            downloaded += event.data.chunkLength;
            setState({
              phase: "downloading",
              progress: downloaded,
              total: contentLength,
            });
            break;
          case "Finished":
            setState({ phase: "ready" });
            break;
        }
      });

      setState({ phase: "ready" });
    } catch (err) {
      setState({
        phase: "error",
        message: err instanceof Error ? err.message : String(err),
      });
    }
  };

  const handleRestart = async () => {
    const { relaunch } = await import("@tauri-apps/plugin-process");
    await relaunch();
  };

  // Don't render if idle or dismissed
  if (state.phase === "idle" || dismissed) return null;

  // ---------------------------------------------------------------------------
  // Progress bar helper
  // ---------------------------------------------------------------------------

  const progressPct =
    state.phase === "downloading" && state.total > 0
      ? Math.round((state.progress / state.total) * 100)
      : 0;

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  return (
    <div
      className={cn(
        "fixed bottom-4 right-4 z-50 w-80 rounded-xl border shadow-2xl backdrop-blur-md p-4 animate-fade-in",
        state.phase === "error"
          ? "border-red-500/30 bg-red-950/90"
          : "border-brand-500/30 bg-gray-900/95",
      )}
    >
      {/* Close button (available & error phases only) */}
      {(state.phase === "available" || state.phase === "error") && (
        <button
          onClick={() => setDismissed(true)}
          className="absolute top-2 right-2 p-1 rounded-md text-gray-500 hover:text-gray-300 hover:bg-gray-800 transition-colors"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      )}

      {/* ── Available ── */}
      {state.phase === "available" && (
        <div className="space-y-3">
          <div>
            <p className="text-sm font-medium text-gray-100">
              AgentArmor Studio v{state.info.version} is available
            </p>
            {state.info.body && (
              <p className="text-[11px] text-gray-500 mt-1 line-clamp-2">
                {state.info.body}
              </p>
            )}
          </div>
          <div className="flex items-center gap-2">
            <Button size="sm" onClick={handleUpdate} className="gap-1.5 text-xs flex-1">
              <Download className="h-3 w-3" />
              Update Now
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setDismissed(true)}
              className="text-xs text-gray-500"
            >
              Later
            </Button>
          </div>
        </div>
      )}

      {/* ── Downloading ── */}
      {state.phase === "downloading" && (
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <div className="animate-spin">
              <RefreshCw className="h-4 w-4 text-brand-400" />
            </div>
            <p className="text-sm font-medium text-gray-100">Downloading update…</p>
          </div>
          <div className="space-y-1.5">
            <div className="h-2 w-full rounded-full bg-gray-800 overflow-hidden">
              <div
                className="h-full rounded-full bg-gradient-to-r from-brand-500 to-brand-400 transition-all duration-300"
                style={{ width: `${progressPct}%` }}
              />
            </div>
            <p className="text-[10px] text-gray-500 text-right tabular-nums font-mono">
              {progressPct}%
              {state.total > 0 && (
                <span>
                  {" "}
                  ({(state.progress / 1024 / 1024).toFixed(1)} /{" "}
                  {(state.total / 1024 / 1024).toFixed(1)} MB)
                </span>
              )}
            </p>
          </div>
        </div>
      )}

      {/* ── Ready to restart ── */}
      {state.phase === "ready" && (
        <div className="space-y-3">
          <p className="text-sm font-medium text-emerald-400">
            ✓ Update installed successfully
          </p>
          <Button size="sm" onClick={handleRestart} className="gap-1.5 text-xs w-full">
            <RefreshCw className="h-3 w-3" />
            Restart Now
          </Button>
        </div>
      )}

      {/* ── Error ── */}
      {state.phase === "error" && (
        <div className="space-y-2">
          <p className="text-sm font-medium text-red-400">Update failed</p>
          <p className="text-[11px] text-red-400/70 line-clamp-2">{state.message}</p>
          <Button
            variant="ghost"
            size="sm"
            onClick={handleUpdate}
            className="text-xs text-red-400"
          >
            Retry
          </Button>
        </div>
      )}
    </div>
  );
}
