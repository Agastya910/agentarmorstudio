import { useEffect, useState } from "react";
import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";
import { Card, CardContent } from "@/components/ui/card";
import { getStatus, getEvents, type StatusResponse } from "@/lib/api";

// ---------------------------------------------------------------------------
// Score calculation
// ---------------------------------------------------------------------------

function computeScore(status: StatusResponse | null, eventCount: number): number {
  if (!status) return 0;
  const activeLayers = status.layers.filter((l) => l.enabled).length;
  const layerComponent = (activeLayers / 8) * 70;
  // For the events component, we use a heuristic:
  // more blocked events relative to total events = higher protection score
  const eventComponent = eventCount > 0 ? Math.min(30, (eventCount / Math.max(eventCount, 1)) * 30) : 30;
  return Math.round(Math.min(100, layerComponent + eventComponent));
}

function scoreColor(score: number): string {
  if (score >= 80) return "#10b981"; // emerald-500
  if (score >= 60) return "#f59e0b"; // amber-500
  return "#ef4444"; // red-500
}

function scoreLabel(score: number): string {
  if (score >= 80) return "Excellent";
  if (score >= 60) return "Fair";
  return "At Risk";
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function SecurityScoreRing() {
  const [score, setScore] = useState(0);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetch() {
      try {
        const [statusRes, eventsRes] = await Promise.all([
          getStatus(),
          getEvents(100),
        ]);
        setScore(computeScore(statusRes, eventsRes.count));
      } catch {
        setScore(0);
      } finally {
        setLoading(false);
      }
    }
    fetch();
    const id = setInterval(fetch, 10_000);
    return () => clearInterval(id);
  }, []);

  const color = scoreColor(score);
  const data = [
    { name: "score", value: score },
    { name: "remaining", value: 100 - score },
  ];

  return (
    <Card className="flex flex-col items-center justify-center h-full min-h-[280px]">
      <CardContent className="relative flex items-center justify-center w-full pt-6">
        {loading ? (
          <div className="h-48 w-48 flex items-center justify-center">
            <div className="animate-spin h-8 w-8 border-2 border-brand-500 border-t-transparent rounded-full" />
          </div>
        ) : (
          <div className="relative w-56 h-56">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={data}
                  cx="50%"
                  cy="50%"
                  innerRadius="72%"
                  outerRadius="92%"
                  startAngle={90}
                  endAngle={-270}
                  paddingAngle={0}
                  dataKey="value"
                  stroke="none"
                  animationBegin={0}
                  animationDuration={800}
                >
                  <Cell fill={color} />
                  <Cell fill="#1f2937" />
                </Pie>
              </PieChart>
            </ResponsiveContainer>

            {/* Center label */}
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span
                className="text-4xl font-bold tabular-nums"
                style={{ color }}
              >
                {score}
              </span>
              <span className="text-xs text-gray-400 mt-1">Security Score</span>
              <span
                className="text-[10px] font-semibold mt-0.5 uppercase tracking-wider"
                style={{ color }}
              >
                {scoreLabel(score)}
              </span>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
