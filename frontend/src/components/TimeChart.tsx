import { useId } from "react";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { fmtAxisTime, fmtDate } from "@/lib/format";

export interface Series {
  key: string;
  label: string;
  /** Feste Reihenfolge der Kategoriefarben – Farbe hängt an der Serie, nicht am Rang */
  slot: 1 | 2 | 3;
}

export type Row = { t: string } & Record<string, number | string | null>;

/** Mehrere {t, v}-Reihen zu Zeilen [{t, a, b}] zusammenführen. */
export function mergeSeries(series: Record<string, { t: string; v: number | null }[]>): Row[] {
  const byTime = new Map<string, Row>();
  for (const [key, points] of Object.entries(series)) {
    for (const p of points) {
      const row: Row = byTime.get(p.t) ?? { t: p.t };
      row[key] = p.v;
      byTime.set(p.t, row);
    }
  }
  return [...byTime.values()].sort((a, b) => a.t.localeCompare(b.t));
}

interface TooltipPayload {
  dataKey: string;
  name: string;
  value: number | null;
}

function ChartTooltip({
  active,
  label,
  payload,
  series,
  format,
}: {
  active?: boolean;
  label?: string;
  payload?: TooltipPayload[];
  series: Series[];
  format: (v: number) => string;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div className="min-w-40 rounded-lg border bg-popover/95 px-3 py-2 text-xs shadow-xl backdrop-blur">
      <div className="mb-1.5 text-muted-foreground">{fmtDate(String(label))}</div>
      {payload.map((p) => {
        const s = series.find((x) => x.key === p.dataKey);
        return (
          <div key={p.dataKey} className="flex items-center justify-between gap-4">
            <span className="flex items-center gap-1.5 text-muted-foreground">
              <span className="h-0.5 w-3 rounded" style={{ background: `var(--series-${s?.slot ?? 1})` }} />
              {p.name}
            </span>
            <span className="font-medium tabular-nums text-foreground">
              {typeof p.value === "number" ? format(p.value) : "–"}
            </span>
          </div>
        );
      })}
    </div>
  );
}

export function TimeChart({
  data,
  series,
  hours,
  format,
  yMax,
  height = 220,
}: {
  data: Row[];
  series: Series[];
  hours: number;
  format: (v: number) => string;
  yMax?: number;
  height?: number;
}) {
  const id = useId().replace(/:/g, "");
  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center text-sm text-muted-foreground" style={{ height }}>
        Keine Daten im Zeitraum
      </div>
    );
  }
  return (
    <div>
      {series.length > 1 && (
        <ul className="mb-3 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground" aria-label="Legende">
          {series.map((s) => (
            <li key={s.key} className="flex items-center gap-1.5">
              <span className="inline-block h-0.5 w-4 rounded" style={{ background: `var(--series-${s.slot})` }} />
              {s.label}
            </li>
          ))}
        </ul>
      )}
      <ResponsiveContainer width="100%" height={height}>
        <AreaChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
          <defs>
            {series.map((s) => (
              <linearGradient key={s.key} id={`${id}-${s.key}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={`var(--series-${s.slot})`} stopOpacity={0.28} />
                <stop offset="100%" stopColor={`var(--series-${s.slot})`} stopOpacity={0} />
              </linearGradient>
            ))}
          </defs>
          <CartesianGrid vertical={false} stroke="var(--grid)" />
          <XAxis
            dataKey="t"
            tickFormatter={(t: string) => fmtAxisTime(t, hours)}
            tick={{ fill: "var(--muted-foreground)", fontSize: 11 }}
            axisLine={false}
            tickLine={false}
            minTickGap={40}
          />
          <YAxis
            tickFormatter={(v: number) => format(v)}
            tick={{ fill: "var(--muted-foreground)", fontSize: 11 }}
            axisLine={false}
            tickLine={false}
            width={72}
            domain={[0, yMax ?? "auto"]}
          />
          <Tooltip
            cursor={{ stroke: "var(--muted-foreground)", strokeDasharray: "3 3", strokeOpacity: 0.5 }}
            content={<ChartTooltip series={series} format={format} />}
          />
          {series.map((s) => (
            <Area
              key={s.key}
              type="monotone"
              dataKey={s.key}
              name={s.label}
              stroke={`var(--series-${s.slot})`}
              strokeWidth={2}
              fill={`url(#${id}-${s.key})`}
              dot={false}
              activeDot={{ r: 4, stroke: "var(--card)", strokeWidth: 2 }}
              connectNulls
              isAnimationActive={false}
            />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
