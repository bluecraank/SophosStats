import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Card, Empty, ErrorBox, Loading } from "../../components/ui";
import { api } from "../../lib/api";
import { fmtDate } from "../../lib/format";

interface ConfigType {
  entity_type: string;
  count: number;
}
interface ConfigObject {
  name: string;
  data: unknown;
  updated_at?: string;
}
interface ConfigAt {
  time: string;
  clamped: boolean;
  types: Record<string, number>;
  objects: ConfigObject[];
}

export function ConfigTab({ fwId }: { fwId: number }) {
  const [type, setType] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  // Leer = aktueller Stand, sonst rekonstruierter Stand am Ende des gewählten Tages
  const [date, setDate] = useState("");
  const at = date ? `${date}T23:59:59Z` : null;

  const current = useQuery({
    queryKey: ["config-types", fwId],
    queryFn: () => api<ConfigType[]>(`/api/firewalls/${fwId}/config/types`),
    enabled: !at,
  });
  const historic = useQuery({
    queryKey: ["config-at", fwId, at],
    queryFn: () => api<ConfigAt>(`/api/firewalls/${fwId}/config/at`, { params: { time: at } }),
    enabled: !!at,
  });

  const types: ConfigType[] = at
    ? Object.entries(historic.data?.types ?? {}).map(([entity_type, count]) => ({ entity_type, count }))
    : (current.data ?? []);
  const selected = type && types.some((t) => t.entity_type === type) ? type : (types[0]?.entity_type ?? null);

  const objects = useQuery({
    queryKey: ["config", fwId, selected],
    queryFn: () => api<ConfigObject[]>(`/api/firewalls/${fwId}/config`, { params: { entity_type: selected } }),
    enabled: !at && !!selected,
  });
  const historicObjects = useQuery({
    queryKey: ["config-at", fwId, at, selected],
    queryFn: () => api<ConfigAt>(`/api/firewalls/${fwId}/config/at`, { params: { time: at, entity_type: selected } }),
    enabled: !!at && !!selected,
  });
  const list = at ? historicObjects.data?.objects : objects.data;

  const loading = at ? historic.isPending : current.isPending;
  const error = at ? historic.error : current.error;
  const shown = (list ?? []).filter((o) => o.name.toLowerCase().includes(filter.toLowerCase()));

  return (
    <div className="space-y-4">
      <label className="flex flex-wrap items-center gap-2 text-sm text-ink-2">
        Stand am
        <input type="date" className="input w-auto" value={date} max={new Date().toISOString().slice(0, 10)} onChange={(e) => setDate(e.target.value)} />
        {date ? (
          <button className="btn-secondary py-1" onClick={() => setDate("")}>Aktueller Stand</button>
        ) : (
          <span className="text-xs text-muted">leer = aktuell</span>
        )}
      </label>
      {at && historic.data?.clamped && (
        <p className="text-xs text-muted">Die Historie beginnt am {fmtDate(historic.data.time)} – angezeigt wird der früheste bekannte Stand.</p>
      )}
      <ErrorBox error={error} />
      {loading ? (
        <Loading />
      ) : types.length === 0 ? (
        <Empty>Noch keine Konfiguration abgerufen</Empty>
      ) : (
        <div className="grid gap-4 lg:grid-cols-[16rem_1fr]">
          <Card title="Objekttypen">
            <ul className="-mx-2 space-y-0.5">
              {types.map((t) => (
                <li key={t.entity_type}>
                  <button
                    onClick={() => setType(t.entity_type)}
                    className={`flex w-full cursor-pointer justify-between rounded px-2 py-1.5 text-sm ${
                      selected === t.entity_type ? "bg-accent/12 font-medium" : "hover:bg-surface-2"
                    }`}
                  >
                    <span>{t.entity_type}</span>
                    <span className="text-ink-2">{t.count}</span>
                  </button>
                </li>
              ))}
            </ul>
          </Card>
          <Card
            title={`${selected}${date ? ` – Stand ${new Date(date).toLocaleDateString("de-DE")}` : ""}`}
            actions={<input className="input w-56" placeholder="Filtern" value={filter} onChange={(e) => setFilter(e.target.value)} />}
          >
            {!list ? (
              <Loading />
            ) : (
              <div className="space-y-2">
                {shown.map((o) => (
                  <details key={o.name} className="rounded-md border border-line">
                    <summary className="flex cursor-pointer justify-between gap-2 px-3 py-2 text-sm">
                      <span className="font-medium">{o.name}</span>
                      {o.updated_at && <span className="text-xs text-muted">geändert {fmtDate(o.updated_at)}</span>}
                    </summary>
                    <pre className="overflow-x-auto border-t border-line bg-surface-2 p-3 text-xs">{JSON.stringify(o.data, null, 2)}</pre>
                  </details>
                ))}
              </div>
            )}
          </Card>
        </div>
      )}
    </div>
  );
}
