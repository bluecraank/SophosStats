import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Empty, ErrorBox, Loading, StatTile, StatusBadge, type Status } from "../../components/ui";
import { api } from "../../lib/api";
import { fmtDate } from "../../lib/format";
import type { AuditFinding, AuditResult, FindingKind } from "../../lib/types";

export const KIND_LABEL: Record<FindingKind, string> = {
  shadowed: "Verdeckt",
  redundant: "Redundant",
  too_broad: "Zu breit",
  unused: "Ungenutzt",
  no_logging: "Ohne Logging",
  disabled: "Deaktiviert",
};

const KIND_HINT: Record<FindingKind, string> = {
  shadowed: "Eine Regel weiter oben greift zuerst mit anderer Aktion – diese Regel wirkt nie.",
  redundant: "Eine Regel weiter oben erlaubt/blockiert bereits dasselbe – kann entfernt werden.",
  too_broad: "Any → Any mit allen Diensten. Das Nutzungsprofil zeigt, was tatsächlich gebraucht wird.",
  unused: "Kein Treffer im gewählten Zeitraum – Kandidat zum Deaktivieren.",
  no_logging: "Ohne „Log firewall traffic“ sind Nutzung und ungenutzte Regeln nicht erkennbar.",
  disabled: "Deaktivierte Regeln machen das Regelwerk unübersichtlich.",
};

export const SEVERITY: Record<AuditFinding["severity"], { status: Status; label: string }> = {
  high: { status: "critical", label: "Hoch" },
  medium: { status: "warning", label: "Mittel" },
  low: { status: "off", label: "Niedrig" },
  info: { status: "off", label: "Info" },
};

const KINDS: FindingKind[] = ["shadowed", "redundant", "too_broad", "unused", "no_logging", "disabled"];

export function FindingRow({ f }: { f: AuditFinding }) {
  return (
    <li className="flex flex-wrap items-start gap-x-3 gap-y-1 border-t border-line px-3 py-2 first:border-t-0">
      <span className="w-20 shrink-0">
        <StatusBadge status={SEVERITY[f.severity].status} label={SEVERITY[f.severity].label} />
      </span>
      <span className="w-24 shrink-0 text-xs text-ink-2">{KIND_LABEL[f.kind]}</span>
      <span className="min-w-0 flex-1">
        <span className="font-medium">
          {f.position != null && <span className="text-ink-2">#{f.position + 1} </span>}
          {f.rule}
        </span>
        <span className="block text-sm text-ink-2">{f.message}</span>
        {f.profile && (
          <span className="block text-xs text-muted">
            Tatsächlich genutzt (Zeitraum): {f.profile.sources} Quellen · {f.profile.destinations} Ziele · {f.profile.ports} Zielports
            – Details im Tab „Regeln“ beim Aufklappen der Regel
          </span>
        )}
      </span>
    </li>
  );
}

export function AuditTab({ fwId }: { fwId: number }) {
  const [days, setDays] = useState(30);
  const [kind, setKind] = useState<FindingKind | null>(null);
  const q = useQuery({
    queryKey: ["audit", fwId, days],
    queryFn: () => api<AuditResult>(`/api/firewalls/${fwId}/audit`, { params: { unused_days: days } }),
  });
  if (q.isPending) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const a = q.data;
  const shown = kind ? a.findings.filter((f) => f.kind === kind) : a.findings;
  const enoughData = a.data_since && Date.now() - new Date(a.data_since).getTime() >= days * 86400_000;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-ink-2">
          {a.rule_count} Regeln, davon {a.enabled_count} aktiv. Nutzungsdaten seit {fmtDate(a.data_since)}.
        </p>
        <label className="flex items-center gap-2 text-sm text-ink-2">
          Ungenutzt seit
          <select className="input w-auto" value={days} onChange={(e) => setDays(Number(e.target.value))}>
            {[7, 30, 60, 90, 180, 365].map((d) => (
              <option key={d} value={d}>{d} Tagen</option>
            ))}
          </select>
        </label>
      </div>
      {!enoughData && (
        <div className="rounded-md border border-warning/50 bg-warning/10 px-3 py-2 text-sm" role="status">
          Für „ungenutzt seit {days} Tagen“ reichen die gesammelten Logs noch nicht – diese Prüfung startet, sobald genug Daten da sind.
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        {KINDS.map((k) => (
          <button key={k} onClick={() => setKind(kind === k ? null : k)} className="cursor-pointer text-left" aria-pressed={kind === k} title={KIND_HINT[k]}>
            <div className={kind === k ? "rounded-lg ring-2 ring-accent" : ""}>
              <StatTile label={KIND_LABEL[k]} value={a.summary[k] ?? 0} />
            </div>
          </button>
        ))}
      </div>
      {kind && <p className="text-sm text-ink-2">{KIND_HINT[kind]}</p>}

      {shown.length === 0 ? (
        <Empty>{kind ? "Keine Befunde in dieser Kategorie" : "Keine Befunde – das Regelwerk sieht sauber aus"}</Empty>
      ) : (
        <ul className="rounded-lg border border-line bg-surface">
          {shown.map((f, i) => (
            <FindingRow key={`${f.kind}-${f.rule}-${i}`} f={f} />
          ))}
        </ul>
      )}
      <p className="text-xs text-muted">
        „Verdeckt“ und „Redundant“ vergleichen Zonen, Netze, Dienste, Identitäten und Zeitplan über die Objektnamen.
        Gruppeninhalte und überlappende IP-Bereiche werden nicht aufgelöst – es werden nur eindeutige Fälle gemeldet.
      </p>
    </div>
  );
}
