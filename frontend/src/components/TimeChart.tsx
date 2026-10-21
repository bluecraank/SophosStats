import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { fmtAxisTime, fmtDate } from "../lib/format";

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
  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center text-sm text-muted" style={{ height }}>
        Keine Daten im Zeitraum
      </div>
    );
  }
  return (
    <div>
      {series.length > 1 && (
        <ul className="mb-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-ink-2" aria-label="Legende">
          {series.map((s) => (
            <li key={s.key} className="flex items-center gap-1.5">
              <span className="inline-block h-0.5 w-4 rounded" style={{ background: `var(--series-${s.slot})` }} />
              {s.label}
            </li>
          ))}
        </ul>
      )}
      <ResponsiveContainer width="100%" height={height}>
        <LineChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
          <CartesianGrid vertical={false} stroke="var(--grid)" />
          <XAxis
            dataKey="t"
            tickFormatter={(t: string) => fmtAxisTime(t, hours)}
            tick={{ fill: "var(--muted)", fontSize: 11 }}
            axisLine={{ stroke: "var(--border)" }}
            tickLine={false}
            minTickGap={40}
          />
          <YAxis
            tickFormatter={(v: number) => format(v)}
            tick={{ fill: "var(--muted)", fontSize: 11 }}
            axisLine={false}
            tickLine={false}
            width={72}
            domain={[0, yMax ?? "auto"]}
          />
          <Tooltip
            cursor={{ stroke: "var(--muted)", strokeDasharray: "3 3" }}
            contentStyle={{
              background: "var(--surface)",
              border: "1px solid var(--border)",
              borderRadius: 6,
              fontSize: 12,
              color: "var(--text)",
            }}
            labelStyle={{ color: "var(--text-2)" }}
            itemStyle={{ color: "var(--text)" }}
            labelFormatter={(t) => fmtDate(String(t))}
            formatter={(v, name) => [typeof v === "number" ? format(v) : "–", name]}
          />
          {series.map((s) => (
            <Line
              key={s.key}
              dataKey={s.key}
              name={s.label}
              stroke={`var(--series-${s.slot})`}
              strokeWidth={2}
              dot={false}
              activeDot={{ r: 4, stroke: "var(--surface)", strokeWidth: 2 }}
              connectNulls
              isAnimationActive={false}
            />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
