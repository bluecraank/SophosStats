import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Clock, TriangleAlert, UserRound } from "lucide-react";
import { DiffView } from "@/components/DiffView";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
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

export function Actors({ actors }: { actors: ChangeActor[] }) {
  if (actors.length === 0) {
    return (
      <span className="inline-flex items-center gap-1 text-xs text-muted-foreground/70" title="Kein passendes Admin-Event im Syslog gefunden">
        <UserRound className="size-3.5" /> Benutzer unbekannt
      </span>
    );
  }
  const a = actors[actors.length - 1];
  return (
    <span
      className="inline-flex items-center gap-1 text-xs text-muted-foreground"
      title={actors.map((x) => `${fmtDate(x.time)}: ${x.message}`).join("\n")}
    >
      <UserRound className="size-3.5" />
      {a.exact ? "von" : "vermutlich von"} <strong className="text-foreground">{a.user ?? "?"}</strong>
      {a.src_ip && ` (${a.src_ip}${a.via ? `, ${a.via}` : ""})`}
    </span>
  );
}

const fmtTime = (iso: string) => new Date(iso).toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" });

/** Wann geändert: exakt aus dem Admin-Event, sonst das Zeitfenster zwischen zwei Abrufen. */
export function ChangeTime({ c }: { c: ConfigChange }) {
  const exact = c.actors.findLast((a) => a.exact);
  let text: string;
  if (exact) text = fmtDate(exact.time);
  else if (c.window_start) {
    const sameDay = new Date(c.window_start).toDateString() === new Date(c.time).toDateString();
    text = sameDay
      ? `${new Date(c.time).toLocaleDateString("de-DE")} zwischen ${fmtTime(c.window_start)} und ${fmtTime(c.time)}`
      : `zwischen ${fmtDate(c.window_start)} und ${fmtDate(c.time)}`;
  } else text = `bis ${fmtDate(c.time)}`;
  return (
    <span className="inline-flex items-center gap-1 text-xs text-muted-foreground" title={`Erkannt beim Abruf ${fmtDate(c.time)}`}>
      <Clock className="size-3.5" /> {text}
    </span>
  );
}

function AdminEventsHint({ fwId }: { fwId: number }) {
  const q = useQuery({
    queryKey: ["admin-events", fwId],
    queryFn: () => api<{ count_7d: number; last_at: string | null }>(`/api/firewalls/${fwId}/admin-events/status`),
  });
  if (!q.data || q.data.count_7d > 0) return null;
  return (
    <Alert className="border-warning/40 bg-warning/5">
      <TriangleAlert className="text-warning" />
      <AlertTitle>Keine Admin-Events empfangen – Benutzer kann nicht ermittelt werden</AlertTitle>
      <AlertDescription>
        Auf der XGS unter <em>System services → Log settings</em> beim Syslog-Server die Kategorie{" "}
        <strong>Events → Admin events</strong> aktivieren. Danach erscheint bei neuen Änderungen, wer sie wann vorgenommen hat.
      </AlertDescription>
    </Alert>
  );
}

function ChangeDetails({ old, next }: { old: unknown; next: unknown }) {
  const keys = changedKeys(old, next);
  return (
    <div className="space-y-2 border-t border-border bg-muted/30 p-3">
      {keys.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
          Geänderte Felder:
          {keys.map((k) => (
            <Pill key={k} tone="accent">{k}</Pill>
          ))}
        </div>
      )}
      <DiffView
        left={old}
        right={next}
        leftTitle={old == null ? "Vorher (nicht vorhanden)" : "Vorher"}
        rightTitle={next == null ? "Nachher (entfernt)" : "Nachher"}
      />
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
      <AdminEventsHint fwId={fwId} />
      {q.data.map((c, i) => (
        <details key={c.id} open={i === 0} className="rounded-md border border-border bg-card">
          <summary className="flex cursor-pointer flex-wrap items-center gap-x-3 gap-y-1.5 px-3 py-2.5 text-sm">
            <Pill tone={actionTone(c.action)}>{ACTION_LABEL[c.action]}</Pill>
            <span className="text-muted-foreground">{c.entity_type}</span>
            <span className="font-medium">{c.name}</span>
            <span className="ml-auto flex flex-wrap items-center gap-x-4 gap-y-1">
              <ChangeTime c={c} />
              <Actors actors={c.actors} />
            </span>
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
      <label className="flex items-center gap-2 text-sm text-muted-foreground">
        Konfiguration vom
        <input type="date" className="input w-auto" value={date} max={new Date().toISOString().slice(0, 10)} onChange={(e) => setDate(e.target.value)} />
        mit heute vergleichen
      </label>
      <ErrorBox error={q.error} />
      {q.isPending && <Loading />}
      {q.data && (
        <>
          {q.data.clamped && (
            <p className="text-xs text-muted-foreground/70">Die Historie beginnt am {fmtDate(q.data.time)} – verglichen wird mit diesem frühesten bekannten Stand.</p>
          )}
          <p className="text-sm text-muted-foreground">
            {q.data.items.length === 0
              ? "Keine Unterschiede."
              : (["added", "modified", "removed"] as Action[])
                  .filter((a) => q.data.summary[a])
                  .map((a) => `${q.data.summary[a]} ${ACTION_LABEL[a]}`)
                  .join(" · ")}
          </p>
          <div className="space-y-2">
            {q.data.items.map((d) => (
              <details key={`${d.entity_type}/${d.name}`} className="rounded-md border border-border bg-card">
                <summary className="flex cursor-pointer flex-wrap items-center gap-2 px-3 py-2 text-sm">
                  <Pill tone={actionTone(d.action)}>{ACTION_LABEL[d.action]}</Pill>
                  <span className="text-muted-foreground">{d.entity_type}</span>
                  <span className="font-medium">{d.name}</span>
                  {d.changes > 1 && <span className="text-xs text-muted-foreground/70">({d.changes} Einzeländerungen)</span>}
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
      <div className="inline-flex rounded-md border border-border bg-card p-0.5" role="group">
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
            className={`cursor-pointer rounded px-3 py-1 text-sm ${mode === id ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-muted"}`}
          >
            {label}
          </button>
        ))}
      </div>
      {mode === "history" ? <History fwId={fwId} /> : <Since fwId={fwId} />}
      <p className="text-xs text-muted-foreground/70">
        „von …“ wird aus den Admin-Events im Syslog ermittelt (Log-Kategorie „Admin“ bzw. Events auf der Firewall aktivieren).
      </p>
    </div>
  );
}
