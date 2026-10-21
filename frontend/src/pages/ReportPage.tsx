import { useQuery } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";
import { Link, useParams } from "react-router";
import { ErrorBox, Loading, Pill, StatusBadge } from "../components/ui";
import { api } from "../lib/api";
import { fmtBytes, fmtDate, fmtNumber, fmtPercent } from "../lib/format";
import type { AuditResult, ConfigChange, Firewall } from "../lib/types";
import { KIND_LABEL, SEVERITY } from "./firewall/AuditTab";
import { ACTION_LABEL, actionTone } from "./firewall/ChangesTab";

interface Report {
  generated_at: string;
  firewall: Firewall;
  start: string;
  end: string;
  metrics: Record<string, { avg: number; max: number }>;
  traffic: { hits: number; denied: number; sent_bytes: number; recv_bytes: number };
  top_rules: { name: string; position: number; action: string | null; hits: number; sent_bytes: number; recv_bytes: number }[];
  top_blocked_sources: { src_ip: string; hits: number }[];
  changes: ConfigChange[];
  change_summary: Record<string, number>;
  admin_events: number;
  audit: AuditResult;
}

const day = (d: Date) => d.toISOString().slice(0, 10);

function presets() {
  const now = new Date();
  const firstThis = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
  const firstPrev = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1));
  const lastPrev = new Date(firstThis.getTime() - 86400_000);
  return [
    { label: "Letzter Monat", from: day(firstPrev), to: day(lastPrev) },
    { label: "Aktueller Monat", from: day(firstThis), to: day(now) },
    { label: "Letzte 30 Tage", from: day(new Date(now.getTime() - 29 * 86400_000)), to: day(now) },
    { label: "Letzte 7 Tage", from: day(new Date(now.getTime() - 6 * 86400_000)), to: day(now) },
  ];
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="break-inside-avoid space-y-2">
      <h2 className="border-b border-line pb-1 text-base font-semibold">{title}</h2>
      {children}
    </section>
  );
}

function Kpi({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="rounded-md border border-line px-3 py-2">
      <div className="text-xs text-ink-2">{label}</div>
      <div className="text-lg font-semibold">{value}</div>
    </div>
  );
}

const th = "py-1 pr-3 text-left text-xs font-medium text-ink-2";
const td = "py-1 pr-3 align-top";

export function ReportPage() {
  const id = Number(useParams().id);
  const [range, setRange] = useState(() => presets()[0]);
  const q = useQuery({
    queryKey: ["report", id, range.from, range.to],
    queryFn: () =>
      api<Report>(`/api/firewalls/${id}/report`, {
        params: { start: `${range.from}T00:00:00Z`, end: `${day(new Date(new Date(range.to).getTime() + 86400_000))}T00:00:00Z` },
      }),
  });
  const r = q.data;
  const high = r?.audit.findings.filter((f) => f.severity === "high").length ?? 0;
  const medium = r?.audit.findings.filter((f) => f.severity === "medium").length ?? 0;

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <div className="flex flex-wrap items-end gap-3 print:hidden">
        <Link to={`/firewalls/${id}`} className="text-sm text-accent hover:underline">← Zurück</Link>
        <div className="flex flex-wrap gap-1">
          {presets().map((p) => (
            <button key={p.label} className={range.label === p.label ? "btn-primary py-1" : "btn-secondary py-1"} onClick={() => setRange(p)}>
              {p.label}
            </button>
          ))}
        </div>
        <label className="text-xs text-ink-2">
          Von <input type="date" className="input w-auto py-1" value={range.from} onChange={(e) => setRange({ ...range, label: "", from: e.target.value })} />
        </label>
        <label className="text-xs text-ink-2">
          Bis <input type="date" className="input w-auto py-1" value={range.to} onChange={(e) => setRange({ ...range, label: "", to: e.target.value })} />
        </label>
        <button className="btn-primary ml-auto" onClick={() => window.print()} disabled={!r}>Drucken / PDF</button>
      </div>

      <ErrorBox error={q.error} />
      {q.isPending && <Loading />}
      {r && (
        <article className="space-y-6 rounded-lg border border-line bg-surface p-6 print:border-0 print:p-0">
          <header>
            <h1 className="text-2xl font-semibold">Firewall-Bericht: {r.firewall.name}</h1>
            <p className="text-sm text-ink-2">
              Zeitraum {new Date(r.start).toLocaleDateString("de-DE")} – {new Date(new Date(r.end).getTime() - 1).toLocaleDateString("de-DE")} ·
              erstellt {fmtDate(r.generated_at)}
            </p>
            <p className="text-sm text-ink-2">
              {r.firewall.host} · {r.firewall.model ?? "?"} · Firmware {r.firewall.firmware ?? "?"}
              {r.firewall.serial && ` · SN ${r.firewall.serial}`}
            </p>
          </header>

          <Section title="Zusammenfassung">
            <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
              <Kpi label="Verbindungen" value={fmtNumber(r.traffic.hits)} />
              <Kpi label="Blockiert" value={fmtNumber(r.traffic.denied)} />
              <Kpi label="Gesendet / Empfangen" value={`${fmtBytes(r.traffic.sent_bytes)} / ${fmtBytes(r.traffic.recv_bytes)}`} />
              <Kpi label="Konfig-Änderungen" value={fmtNumber(r.changes.length)} />
              <Kpi label="Admin-Events" value={fmtNumber(r.admin_events)} />
              <Kpi label="Audit: hoch / mittel" value={`${high} / ${medium}`} />
              <Kpi label="Regeln (aktiv)" value={`${r.audit.rule_count} (${r.audit.enabled_count})`} />
              <Kpi label="Ø CPU / max" value={r.metrics.cpu_percent ? `${fmtPercent(r.metrics.cpu_percent.avg)} / ${fmtPercent(r.metrics.cpu_percent.max)}` : "–"} />
            </div>
          </Section>

          <Section title="Systemauslastung">
            <table className="w-full text-sm">
              <thead><tr><th className={th}>Wert</th><th className={th}>Durchschnitt</th><th className={th}>Maximum</th></tr></thead>
              <tbody>
                {[["cpu_percent", "CPU"], ["memory_percent", "Arbeitsspeicher"], ["disk_percent", "Disk"]].map(([k, label]) => (
                  <tr key={k} className="border-t border-line">
                    <td className={td}>{label}</td>
                    <td className={td}>{fmtPercent(r.metrics[k]?.avg)}</td>
                    <td className={td}>{fmtPercent(r.metrics[k]?.max)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Section>

          <Section title={`Konfigurationsänderungen (${r.changes.length})`}>
            {r.changes.length === 0 ? (
              <p className="text-sm text-ink-2">Keine Änderungen im Zeitraum.</p>
            ) : (
              <table className="w-full text-sm">
                <thead><tr><th className={th}>Erkannt</th><th className={th}>Aktion</th><th className={th}>Typ</th><th className={th}>Objekt</th><th className={th}>Durch</th></tr></thead>
                <tbody>
                  {r.changes.map((c) => {
                    const actor = c.actors.at(-1);
                    return (
                      <tr key={c.id} className="border-t border-line">
                        <td className={`${td} whitespace-nowrap`}>{fmtDate(c.time)}</td>
                        <td className={td}><Pill tone={actionTone(c.action)}>{ACTION_LABEL[c.action]}</Pill></td>
                        <td className={td}>{c.entity_type}</td>
                        <td className={`${td} font-medium`}>{c.name}</td>
                        <td className={td}>{actor ? `${actor.user ?? "?"}${actor.src_ip ? ` (${actor.src_ip})` : ""}` : "–"}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </Section>

          <Section title={`Regel-Audit (${r.audit.findings.length} Befunde)`}>
            {r.audit.findings.length === 0 ? (
              <p className="text-sm text-ink-2">Keine Befunde.</p>
            ) : (
              <table className="w-full text-sm">
                <thead><tr><th className={th}>Schwere</th><th className={th}>Art</th><th className={th}>Regel</th><th className={th}>Befund</th></tr></thead>
                <tbody>
                  {r.audit.findings.map((f, i) => (
                    <tr key={i} className="border-t border-line">
                      <td className={td}><StatusBadge status={SEVERITY[f.severity].status} label={SEVERITY[f.severity].label} /></td>
                      <td className={`${td} whitespace-nowrap`}>{KIND_LABEL[f.kind]}</td>
                      <td className={`${td} font-medium`}>{f.position != null && `#${f.position + 1} `}{f.rule}</td>
                      <td className={td}>{f.message}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <p className="text-xs text-muted">„Ungenutzt“ bezieht sich auf die letzten {r.audit.unused_days} Tage vor Erstellung des Berichts.</p>
          </Section>

          <div className="grid gap-6 md:grid-cols-2 print:grid-cols-2">
            <Section title="Top-Regeln nach Volumen">
              <table className="w-full text-sm">
                <thead><tr><th className={th}>Regel</th><th className={`${th} text-right`}>Treffer</th><th className={`${th} text-right`}>Volumen</th></tr></thead>
                <tbody>
                  {r.top_rules.map((t) => (
                    <tr key={t.name} className="border-t border-line">
                      <td className={td}>#{t.position + 1} {t.name}</td>
                      <td className={`${td} text-right`}>{fmtNumber(t.hits)}</td>
                      <td className={`${td} text-right`}>{fmtBytes(t.sent_bytes + t.recv_bytes)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Section>
            <Section title="Am häufigsten blockierte Quellen">
              <table className="w-full text-sm">
                <thead><tr><th className={th}>Quelle</th><th className={`${th} text-right`}>Blockiert</th></tr></thead>
                <tbody>
                  {r.top_blocked_sources.map((s) => (
                    <tr key={s.src_ip} className="border-t border-line">
                      <td className={`${td} font-mono`}>{s.src_ip}</td>
                      <td className={`${td} text-right`}>{fmtNumber(s.hits)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Section>
          </div>
        </article>
      )}
    </div>
  );
}
