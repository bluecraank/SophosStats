import { useQuery } from "@tanstack/react-query";
import { Empty, ErrorBox, Loading, Pill } from "../../components/ui";
import { api } from "../../lib/api";
import { fmtDate } from "../../lib/format";
import type { ConfigChange } from "../../lib/types";

const ACTION_LABEL = { added: "hinzugefügt", removed: "entfernt", modified: "geändert" } as const;

function JsonBlock({ title, value }: { title: string; value: unknown }) {
  return (
    <div className="min-w-0">
      <div className="mb-1 text-xs font-medium text-ink-2">{title}</div>
      <pre className="max-h-96 overflow-auto rounded border border-line bg-surface p-2 text-xs">{JSON.stringify(value, null, 2)}</pre>
    </div>
  );
}

export function ChangesTab({ fwId }: { fwId: number }) {
  const q = useQuery({
    queryKey: ["changes", fwId],
    queryFn: () => api<ConfigChange[]>(`/api/firewalls/${fwId}/changes`, { params: { limit: 200 } }),
  });
  if (q.isPending) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  if (q.data.length === 0) {
    return <Empty>Keine Änderungen erkannt. Änderungen werden ab dem zweiten Konfigurationsabruf protokolliert.</Empty>;
  }
  return (
    <div className="space-y-2">
      {q.data.map((c) => (
        <details key={c.id} className="rounded-md border border-line bg-surface">
          <summary className="flex cursor-pointer flex-wrap items-center gap-2 px-3 py-2 text-sm">
            <span className="w-36 text-xs text-ink-2">{fmtDate(c.time)}</span>
            <Pill tone={c.action === "added" ? "good" : c.action === "removed" ? "critical" : "accent"}>{ACTION_LABEL[c.action]}</Pill>
            <span className="text-ink-2">{c.entity_type}</span>
            <span className="font-medium">{c.name}</span>
          </summary>
          <div className="grid gap-3 border-t border-line bg-surface-2 p-3 md:grid-cols-2">
            {c.old != null && <JsonBlock title="Vorher" value={c.old} />}
            {c.new != null && <JsonBlock title="Nachher" value={c.new} />}
          </div>
        </details>
      ))}
    </div>
  );
}
