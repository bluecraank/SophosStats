import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Empty, ErrorBox, Loading, Pill } from "../../components/ui";
import { api } from "../../lib/api";
import { fmtDate } from "../../lib/format";
import type { ChangeActor, ConfigChange } from "../../lib/types";

export const ACTION_LABEL = { added: "hinzugefügt", removed: "entfernt", modified: "geändert" } as const;
type Action = keyof typeof ACTION_LABEL;

export const actionTone = (a: Action) => (a === "added" ? "good" : a === "removed" ? "critical" : "accent");

/** Oberste Felder, deren Inhalt sich unterscheidet – macht große JSON-Objekte überblickbar. */
export function changedKeys(oldVal: unknown, newVal: unknown): string[] {
  if (typeof oldVal !== "object" || typeof newVal !== "object" || !oldVal || !newVal) return [];
  const a = oldVal as Record<string, unknown>;
  const b = newVal as Record<string, unknown>;
  return [...new Set([...Object.keys(a), ...Object.keys(b)])].filter((k) => JSON.stringify(a[k]) !== JSON.stringify(b[k]));
}

function JsonBlock({ title, value }: { title: string; value: unknown }) {
  return (
    <div className="min-w-0">
      <div className="mb-1 text-xs font-medium text-ink-2">{title}</div>
      <pre className="max-h-96 overflow-auto rounded border border-line bg-surface p-2 text-xs">{JSON.stringify(value, null, 2)}</pre>
    </div>
  );
}

export function Actors({ actors }: { actors: ChangeActor[] }) {
  if (actors.length === 0) return null;
  const a = actors[actors.length - 1];
  return (
    <span className="text-xs text-ink-2" title={actors.map((x) => `${fmtDate(x.time)}: ${x.message}`).join("\n")}>
      von <strong className="text-ink">{a.user ?? "?"}</strong>
      {a.src_ip && ` (${a.src_ip}${a.via ? `, ${a.via}` : ""})`}
    </span>
  );
}

function ChangeDetails({ old, next }: { old: unknown; next: unknown }) {
  const keys = changedKeys(old, next);
  return (
    <div className="space-y-2 border-t border-line bg-surface-2 p-3">
      {keys.length > 0 && <div className="text-xs text-ink-2">Geänderte Felder: {keys.join(", ")}</div>}
      <div className="grid gap-3 md:grid-cols-2">
        {old != null && <JsonBlock title="Vorher" value={old} />}
        {next != null && <JsonBlock title="Nachher" value={next} />}
      </div>
    </div>
  );
}

function History({ fwId }: { fwId: number }) {
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
            <span
              className="w-36 text-xs text-ink-2"
              title={c.window_start ? `Geändert zwischen ${fmtDate(c.window_start)} und ${fmtDate(c.time)}` : undefined}
            >
              {fmtDate(c.time)}
            </span>
            <Pill tone={actionTone(c.action)}>{ACTION_LABEL[c.action]}</Pill>
            <span className="text-ink-2">{c.entity_type}</span>
            <span className="font-medium">{c.name}</span>
            <Actors actors={c.actors} />
          </summary>
          <ChangeDetails old={c.old} next={c.new} />
        </details>
      ))}
    </div>
  );
}

interface SinceResult {
  time: string;
  clamped: boolean;
  summary: Partial<Record<Action, number>>;
  items: { entity_type: string; name: string; action: Action; old: unknown; new: unknown; changes: number }[];
}

function Since({ fwId }: { fwId: number }) {
  const [date, setDate] = useState(() => new Date(Date.now() - 30 * 86400_000).toISOString().slice(0, 10));
  const q = useQuery({
    queryKey: ["changes-since", fwId, date],
    queryFn: () => api<SinceResult>(`/api/firewalls/${fwId}/changes/since`, { params: { time: `${date}T00:00:00Z` } }),
    enabled: !!date,
  });
  return (
    <div className="space-y-3">
      <label className="flex items-center gap-2 text-sm text-ink-2">
        Konfiguration vom
        <input type="date" className="input w-auto" value={date} max={new Date().toISOString().slice(0, 10)} onChange={(e) => setDate(e.target.value)} />
        mit heute vergleichen
      </label>
      <ErrorBox error={q.error} />
      {q.isPending && <Loading />}
      {q.data && (
        <>
          {q.data.clamped && (
            <p className="text-xs text-muted">Die Historie beginnt am {fmtDate(q.data.time)} – verglichen wird mit diesem frühesten bekannten Stand.</p>
          )}
          <p className="text-sm text-ink-2">
            {q.data.items.length === 0
              ? "Keine Unterschiede."
              : (["added", "modified", "removed"] as Action[])
                  .filter((a) => q.data.summary[a])
                  .map((a) => `${q.data.summary[a]} ${ACTION_LABEL[a]}`)
                  .join(" · ")}
          </p>
          <div className="space-y-2">
            {q.data.items.map((d) => (
              <details key={`${d.entity_type}/${d.name}`} className="rounded-md border border-line bg-surface">
                <summary className="flex cursor-pointer flex-wrap items-center gap-2 px-3 py-2 text-sm">
                  <Pill tone={actionTone(d.action)}>{ACTION_LABEL[d.action]}</Pill>
                  <span className="text-ink-2">{d.entity_type}</span>
                  <span className="font-medium">{d.name}</span>
                  {d.changes > 1 && <span className="text-xs text-muted">({d.changes} Einzeländerungen)</span>}
                </summary>
                <ChangeDetails old={d.old} next={d.new} />
              </details>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

export function ChangesTab({ fwId }: { fwId: number }) {
  const [mode, setMode] = useState<"history" | "since">("history");
  return (
    <div className="space-y-4">
      <div className="inline-flex rounded-md border border-line bg-surface p-0.5" role="group">
        {(
          [
            ["history", "Verlauf"],
            ["since", "Vergleich mit Datum"],
          ] as const
        ).map(([id, label]) => (
          <button
            key={id}
            onClick={() => setMode(id)}
            aria-pressed={mode === id}
            className={`cursor-pointer rounded px-3 py-1 text-sm ${mode === id ? "bg-accent text-accent-ink" : "text-ink-2 hover:bg-surface-2"}`}
          >
            {label}
          </button>
        ))}
      </div>
      {mode === "history" ? <History fwId={fwId} /> : <Since fwId={fwId} />}
      <p className="text-xs text-muted">
        „von …“ wird aus den Admin-Events im Syslog ermittelt (Log-Kategorie „Admin“ bzw. Events auf der Firewall aktivieren).
      </p>
    </div>
  );
}
