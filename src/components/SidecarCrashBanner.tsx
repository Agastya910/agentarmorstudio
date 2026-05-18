import { useEffect, useState } from "react";
import { AlertOctagon, X } from "lucide-react";

/** Listens for `sidecar-crashed` events from Tauri and surfaces a top banner.
 *  No-op in browser dev mode (no Tauri event API). */
export default function SidecarCrashBanner() {
  const [crashInfo, setCrashInfo] = useState<{ exit_status: string } | null>(null);

  useEffect(() => {
    const isTauri =
      typeof window !== "undefined" && !!(window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__;
    if (!isTauri) return;

    let unlisten: (() => void) | null = null;

    (async () => {
      const { listen } = await import("@tauri-apps/api/event");
      unlisten = await listen<{ exit_status: string }>("sidecar-crashed", (event) => {
        setCrashInfo(event.payload);
      });
    })();

    return () => {
      unlisten?.();
    };
  }, []);

  if (!crashInfo) return null;

  return (
    <div className="fixed top-0 left-0 right-0 z-50 bg-red-600/95 border-b border-red-500 text-white px-4 py-3 flex items-center gap-3 shadow-lg">
      <AlertOctagon className="h-5 w-5 flex-none" />
      <div className="flex-1 text-sm">
        <span className="font-semibold">Sidecar crashed.</span>{" "}
        <span className="text-red-100">
          The AgentArmor security pipeline is offline. Restart the app to recover.
        </span>
        <span className="ml-2 text-xs text-red-200 font-mono">({crashInfo.exit_status})</span>
      </div>
      <button
        onClick={() => setCrashInfo(null)}
        className="flex-none text-red-100 hover:text-white transition-colors"
        aria-label="Dismiss"
      >
        <X className="h-4 w-4" />
      </button>
    </div>
  );
}
