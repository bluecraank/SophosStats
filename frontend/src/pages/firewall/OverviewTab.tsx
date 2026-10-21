import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { mergeSeries, TimeChart } from "../../components/TimeChart";
import { Card, ErrorBox, RangeSelect, StatTile } from "../../components/ui";
import { api } from "../../lib/api";
import { fmtNumber, fmtPercent, fmtUptime } from "../../lib/format";
import type { MetricPoint } from "../../lib/types";

interface MetricsResponse {
  bucket_seconds: number;
  series: Record<string, MetricPoint[]>;
}

const pct = (v: number) => `${v.toFixed(0)} %`;

export function OverviewTab({ fwId }: { fwId: number }) {
  const [hours, setHours] = useState(24);
  const q = useQuery({
    queryKey: ["metrics", fwId, hours],
    queryFn: () => api<MetricsResponse>(`/api/firewalls/${fwId}/metrics`, { params: { hours } }),
    refetchInterval: 60_000,
  });
  const s = q.data?.series ?? {};
  const last = (name: string) => s[name]?.at(-1)?.v;

  const usage = mergeSeries({
    cpu: s.cpu_percent ?? [],
    memory: s.memory_percent ?? [],
    disk: s.disk_percent ?? [],
  });
  const users = mergeSeries({ users: s.live_users ?? [] });

  return (
    <div className="space-y-4">
      <div className="flex justify-end">
        <RangeSelect value={hours} onChange={setHours} />
      </div>
      <ErrorBox error={q.error} />
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <StatTile label="CPU" value={fmtPercent(last("cpu_percent"))} />
        <StatTile label="Arbeitsspeicher" value={fmtPercent(last("memory_percent"))} hint={last("memory_capacity_mb") ? `von ${fmtNumber(last("memory_capacity_mb"))} MB` : undefined} />
        <StatTile label="Disk" value={fmtPercent(last("disk_percent"))} hint={last("disk_capacity_mb") ? `von ${fmtNumber(last("disk_capacity_mb"))} MB` : undefined} />
        <StatTile label="Swap" value={fmtPercent(last("swap_percent"))} />
        <StatTile label="Live-Benutzer" value={fmtNumber(last("live_users"))} />
        <StatTile label="Uptime" value={fmtUptime(last("uptime_ticks"))} />
      </div>
      <Card title="Auslastung">
        <TimeChart
          data={usage}
          hours={hours}
          format={pct}
          yMax={100}
          series={[
            { key: "cpu", label: "CPU", slot: 1 },
            { key: "memory", label: "Arbeitsspeicher", slot: 2 },
            { key: "disk", label: "Disk", slot: 3 },
          ]}
        />
      </Card>
      <Card title="Live-Benutzer">
        <TimeChart data={users} hours={hours} format={(v) => fmtNumber(Math.round(v))} series={[{ key: "users", label: "Benutzer", slot: 1 }]} height={160} />
      </Card>
    </div>
  );
}
