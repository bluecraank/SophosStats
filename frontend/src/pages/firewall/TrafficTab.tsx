import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { TimeChart, type Row } from "../../components/TimeChart";
import { Card, Empty, ErrorBox, Loading, RangeSelect, StatusBadge } from "../../components/ui";
import { api } from "../../lib/api";
import { fmtBps } from "../../lib/format";

interface InterfacesResponse {
  latest: { interface: string; in_bps: number | null; out_bps: number | null; oper_up: boolean | null }[];
  series: { t: string; interface: string; in_bps: number | null; out_bps: number | null }[];
}

export function TrafficTab({ fwId }: { fwId: number }) {
  const [hours, setHours] = useState(24);
  const [selected, setSelected] = useState<string | null>(null);
  const q = useQuery({
    queryKey: ["interfaces", fwId, hours],
    queryFn: () => api<InterfacesResponse>(`/api/firewalls/${fwId}/interfaces`, { params: { hours } }),
    refetchInterval: 60_000,
  });
  if (q.isPending) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;

  // Aktive Interfaces zuerst, dann nach aktuellem Durchsatz
  const latest = [...q.data.latest].sort(
    (a, b) => Number(b.oper_up) - Number(a.oper_up) || (b.in_bps ?? 0) + (b.out_bps ?? 0) - ((a.in_bps ?? 0) + (a.out_bps ?? 0)),
  );
  const current = selected ?? latest[0]?.interface;
  const rows: Row[] = q.data.series
    .filter((r) => r.interface === current)
    .map((r) => ({ t: r.t, in: r.in_bps, out: r.out_bps }));

  if (latest.length === 0) return <Empty>Noch keine Interface-Daten (SNMP prüfen)</Empty>;

  return (
    <div className="grid gap-4 lg:grid-cols-[18rem_1fr]">
      <Card title="Interfaces">
        <ul className="-mx-2 space-y-0.5">
          {latest.map((i) => (
            <li key={i.interface}>
              <button
                onClick={() => setSelected(i.interface)}
                className={`flex w-full cursor-pointer items-center justify-between gap-2 rounded px-2 py-1.5 text-left text-sm ${
                  current === i.interface ? "bg-accent/12" : "hover:bg-surface-2"
                }`}
              >
                <StatusBadge status={i.oper_up == null ? "off" : i.oper_up ? "good" : "critical"} label={i.interface} />
                <span className="text-right text-xs text-ink-2">
                  ↓ {fmtBps(i.in_bps)}
                  <br />↑ {fmtBps(i.out_bps)}
                </span>
              </button>
            </li>
          ))}
        </ul>
      </Card>
      <Card title={`Durchsatz ${current}`} actions={<RangeSelect value={hours} onChange={setHours} />}>
        <TimeChart
          data={rows}
          hours={hours}
          format={fmtBps}
          height={300}
          series={[
            { key: "in", label: "Eingehend", slot: 1 },
            { key: "out", label: "Ausgehend", slot: 2 },
          ]}
        />
      </Card>
    </div>
  );
}
