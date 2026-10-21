import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Card, Empty, ErrorBox, Loading } from "../../components/ui";
import { api } from "../../lib/api";
import { fmtDate } from "../../lib/format";

interface ConfigType {
  entity_type: string;
  count: number;
  updated_at: string;
}
interface ConfigObject {
  name: string;
  position: number;
  data: unknown;
  updated_at: string;
}

export function ConfigTab({ fwId }: { fwId: number }) {
  const [type, setType] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const types = useQuery({
    queryKey: ["config-types", fwId],
    queryFn: () => api<ConfigType[]>(`/api/firewalls/${fwId}/config/types`),
  });
  const current = type ?? types.data?.[0]?.entity_type ?? null;
  const objects = useQuery({
    queryKey: ["config", fwId, current],
    queryFn: () => api<ConfigObject[]>(`/api/firewalls/${fwId}/config`, { params: { entity_type: current } }),
    enabled: !!current,
  });

  if (types.isPending) return <Loading />;
  if (types.error) return <ErrorBox error={types.error} />;
  if (types.data.length === 0) return <Empty>Noch keine Konfiguration abgerufen</Empty>;

  const shown = (objects.data ?? []).filter((o) => o.name.toLowerCase().includes(filter.toLowerCase()));

  return (
    <div className="grid gap-4 lg:grid-cols-[16rem_1fr]">
      <Card title="Objekttypen">
        <ul className="-mx-2 space-y-0.5">
          {types.data.map((t) => (
            <li key={t.entity_type}>
              <button
                onClick={() => setType(t.entity_type)}
                className={`flex w-full cursor-pointer justify-between rounded px-2 py-1.5 text-sm ${
                  current === t.entity_type ? "bg-accent/12 font-medium" : "hover:bg-surface-2"
                }`}
              >
                <span>{t.entity_type}</span>
                <span className="text-ink-2">{t.count}</span>
              </button>
            </li>
          ))}
        </ul>
      </Card>
      <Card title={current} actions={<input className="input w-56" placeholder="Filtern" value={filter} onChange={(e) => setFilter(e.target.value)} />}>
        {objects.isPending ? (
          <Loading />
        ) : (
          <div className="space-y-2">
            {shown.map((o) => (
              <details key={o.name} className="rounded-md border border-line">
                <summary className="flex cursor-pointer justify-between gap-2 px-3 py-2 text-sm">
                  <span className="font-medium">{o.name}</span>
                  <span className="text-xs text-muted">geändert {fmtDate(o.updated_at)}</span>
                </summary>
                <pre className="overflow-x-auto border-t border-line bg-surface-2 p-3 text-xs">{JSON.stringify(o.data, null, 2)}</pre>
              </details>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
