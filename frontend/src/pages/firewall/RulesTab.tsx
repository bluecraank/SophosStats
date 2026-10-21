import { useQuery } from "@tanstack/react-query";
import { Fragment, useMemo, useState } from "react";
import { TimeChart, type Row } from "../../components/TimeChart";
import { Card, Empty, ErrorBox, Loading, Pill, RangeSelect } from "../../components/ui";
import { api } from "../../lib/api";
import { fmtBytes, fmtDate, fmtNumber, fmtRelative } from "../../lib/format";
import type { Rule, RulesResponse, TopEntry } from "../../lib/types";

type SortKey = "position" | "hits" | "bytes" | "last_seen";

const list = (items: string[], fallback = "Alle") => (items.length ? items.join(", ") : fallback);
const totalBytes = (r: Rule) => (r.usage ? r.usage.sent_bytes + r.usage.recv_bytes : 0);

export function RulesTab({ fwId }: { fwId: number }) {
  const [hours, setHours] = useState(168);
  const [search, setSearch] = useState("");
  const [onlyUnused, setOnlyUnused] = useState(false);
  const [sort, setSort] = useState<SortKey>("position");
  const [open, setOpen] = useState<string | null>(null);

  const q = useQuery({
    queryKey: ["rules", fwId, hours],
    queryFn: () => api<RulesResponse>(`/api/firewalls/${fwId}/rules`, { params: { hours } }),
    refetchInterval: 60_000,
  });

  const rules = useMemo(() => {
    let r = q.data?.rules ?? [];
    if (search) {
      const s = search.toLowerCase();
      r = r.filter((x) =>
        [x.name, x.description, x.group, ...x.source_zones, ...x.destination_zones, ...x.source_networks, ...x.destination_networks, ...x.services]
          .some((v) => v?.toLowerCase().includes(s)),
      );
    }
    if (onlyUnused) r = r.filter((x) => x.enabled && !x.usage?.hits);
    const sorted = [...r];
    if (sort === "hits") sorted.sort((a, b) => (b.usage?.hits ?? 0) - (a.usage?.hits ?? 0));
    if (sort === "bytes") sorted.sort((a, b) => totalBytes(b) - totalBytes(a));
    if (sort === "last_seen") sorted.sort((a, b) => (b.last_seen_ever ?? "").localeCompare(a.last_seen_ever ?? ""));
    return sorted;
  }, [q.data, search, onlyUnused, sort]);

  if (q.isPending) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const data = q.data;
  const withoutLogging = data.rules.filter((r) => r.enabled && !r.log_traffic).length;

  const SortTh = ({ k, children, right }: { k: SortKey; children: string; right?: boolean }) => (
    <th className={`px-3 py-2 font-medium ${right ? "text-right" : ""}`} aria-sort={sort === k ? "descending" : "none"}>
      <button className="cursor-pointer hover:text-ink" onClick={() => setSort(k)}>
        {children}
        {sort === k && " ▾"}
      </button>
    </th>
  );

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <input className="input w-64" placeholder="Regel, Zone, Netz, Dienst …" value={search} onChange={(e) => setSearch(e.target.value)} />
        <label className="flex items-center gap-2 text-sm text-ink-2">
          <input type="checkbox" checked={onlyUnused} onChange={(e) => setOnlyUnused(e.target.checked)} />
          Nur ungenutzte aktive Regeln
        </label>
        <div className="ml-auto">
          <RangeSelect value={hours} onChange={setHours} />
        </div>
      </div>

      <div className="text-xs text-muted">
        Nutzungswerte werden aus den Firewall-Logs (Syslog) berechnet
        {data.data_since ? ` – Daten seit ${fmtDate(data.data_since)}` : " – bisher keine Logs empfangen"}.
        {withoutLogging > 0 && ` ${withoutLogging} aktive Regel(n) ohne „Log firewall traffic“ – für diese wird keine Nutzung erfasst.`}
      </div>

      {data.rules.length === 0 ? (
        <Empty>Noch keine Regeln abgerufen (XML-API prüfen)</Empty>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-line bg-surface">
          <table className="w-full text-sm">
            <thead className="bg-surface-2 text-left text-xs text-ink-2">
              <tr>
                <SortTh k="position">#</SortTh>
                <th className="px-3 py-2 font-medium">Regel</th>
                <th className="px-3 py-2 font-medium">Aktion</th>
                <th className="px-3 py-2 font-medium">Quelle</th>
                <th className="px-3 py-2 font-medium">Ziel</th>
                <th className="px-3 py-2 font-medium">Dienste</th>
                <SortTh k="hits" right>Treffer</SortTh>
                <SortTh k="bytes" right>Gesendet / Empfangen</SortTh>
                <SortTh k="last_seen">Zuletzt genutzt</SortTh>
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <Fragment key={r.name}>
                  <tr
                    className={`cursor-pointer border-t border-line align-top hover:bg-surface-2 ${r.enabled ? "" : "opacity-55"}`}
                    onClick={() => setOpen(open === r.name ? null : r.name)}
                  >
                    <td className="px-3 py-2 text-ink-2">{r.position + 1}</td>
                    <td className="max-w-64 px-3 py-2">
                      <div className="font-medium">{r.name}</div>
                      <div className="flex flex-wrap gap-1 pt-0.5">
                        {r.group && <Pill>{r.group}</Pill>}
                        {!r.enabled && <Pill>deaktiviert</Pill>}
                        {r.enabled && !r.log_traffic && <Pill>Logging aus</Pill>}
                        {r.policy_type && r.policy_type !== "Network" && <Pill>{r.policy_type}</Pill>}
                      </div>
                    </td>
                    <td className="px-3 py-2">
                      <Pill tone={r.action === "Accept" ? "good" : r.action ? "critical" : "neutral"}>{r.action ?? "–"}</Pill>
                    </td>
                    <td className="max-w-48 px-3 py-2 text-xs">
                      <div>{list(r.source_zones)}</div>
                      <div className="text-ink-2">{list(r.source_networks)}</div>
                    </td>
                    <td className="max-w-48 px-3 py-2 text-xs">
                      <div>{list(r.destination_zones)}</div>
                      <div className="text-ink-2">{list(r.destination_networks)}</div>
                    </td>
                    <td className="max-w-40 px-3 py-2 text-xs">{list(r.services)}</td>
                    <td className="px-3 py-2 text-right font-medium">{fmtNumber(r.usage?.hits ?? 0)}</td>
                    <td className="whitespace-nowrap px-3 py-2 text-right text-xs">
                      {fmtBytes(r.usage?.sent_bytes ?? 0)} / {fmtBytes(r.usage?.recv_bytes ?? 0)}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 text-xs text-ink-2" title={fmtDate(r.last_seen_ever)}>
                      {r.last_seen_ever ? fmtRelative(r.last_seen_ever) : "nie (seit Erfassung)"}
                    </td>
                  </tr>
                  {open === r.name && (
                    <tr className="border-t border-line bg-surface-2">
                      <td colSpan={9} className="p-3">
                        {r.rule_id == null ? (
                          <div className="text-sm text-muted">
                            Für diese Regel wurden noch keine Logs empfangen – Nutzungsdetails erscheinen, sobald Traffic geloggt wird.
                          </div>
                        ) : (
                          <RuleDetail fwId={fwId} ruleId={r.rule_id} hours={hours} />
                        )}
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {data.unmapped_usage.length > 0 && (
        <Card title="Nutzung ohne Regelzuordnung">
          <p className="mb-2 text-xs text-muted">
            Log-Einträge mit Regel-IDs, die keiner abgerufenen Regel per Name zugeordnet werden konnten (z.B. ID 0 = implizite Default-Drop-Regel).
          </p>
          <table className="w-full text-sm">
            <thead className="text-left text-xs text-ink-2">
              <tr>
                <th className="py-1 font-medium">Regel-ID</th>
                <th className="py-1 font-medium">Name im Log</th>
                <th className="py-1 text-right font-medium">Treffer</th>
                <th className="py-1 text-right font-medium">Blockiert</th>
                <th className="py-1 text-right font-medium">Gesendet / Empfangen</th>
              </tr>
            </thead>
            <tbody>
              {data.unmapped_usage.map((u) => (
                <tr key={u.rule_id} className="border-t border-line">
                  <td className="py-1">{u.rule_id}</td>
                  <td className="py-1">{u.rule_name ?? "–"}</td>
                  <td className="py-1 text-right">{fmtNumber(u.hits)}</td>
                  <td className="py-1 text-right">{fmtNumber(u.denied)}</td>
                  <td className="py-1 text-right text-xs">{fmtBytes(u.sent_bytes)} / {fmtBytes(u.recv_bytes)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}

function TopList({ fwId, ruleId, hours, by, title }: { fwId: number; ruleId: number; hours: number; by: string; title: string }) {
  const q = useQuery({
    queryKey: ["top", fwId, ruleId, hours, by],
    queryFn: () => api<TopEntry[]>(`/api/firewalls/${fwId}/top`, { params: { by, hours, rule_id: ruleId, limit: 8 } }),
  });
  return (
    <div className="rounded-md border border-line bg-surface p-3">
      <div className="mb-2 text-xs font-medium text-ink-2">{title}</div>
      {q.data?.length === 0 && <div className="text-xs text-muted">Keine Daten</div>}
      <ol className="space-y-1 text-xs">
        {q.data?.map((e) => (
          <li key={e.key} className="flex justify-between gap-2">
            <span className="truncate font-mono">{e.key}</span>
            <span className="whitespace-nowrap text-ink-2">
              {fmtBytes(e.sent_bytes + e.recv_bytes)} · {fmtNumber(e.hits)}×
            </span>
          </li>
        ))}
      </ol>
    </div>
  );
}

function RuleDetail({ fwId, ruleId, hours }: { fwId: number; ruleId: number; hours: number }) {
  const q = useQuery({
    queryKey: ["rule-series", fwId, ruleId, hours],
    queryFn: () =>
      api<{ series: { t: string; hits: number; sent_bytes: number; recv_bytes: number }[] }>(
        `/api/firewalls/${fwId}/rules/${ruleId}/series`,
        { params: { hours } },
      ),
  });
  const bytes: Row[] = (q.data?.series ?? []).map((p) => ({ t: p.t, sent: p.sent_bytes, recv: p.recv_bytes }));
  const hits: Row[] = (q.data?.series ?? []).map((p) => ({ t: p.t, hits: p.hits }));

  return (
    <div className="space-y-3">
      <div className="grid gap-3 lg:grid-cols-2">
        <div className="rounded-md border border-line bg-surface p-3">
          <div className="mb-2 text-xs font-medium text-ink-2">Datenvolumen</div>
          <TimeChart
            data={bytes}
            hours={hours}
            format={fmtBytes}
            height={180}
            series={[
              { key: "sent", label: "Gesendet", slot: 1 },
              { key: "recv", label: "Empfangen", slot: 2 },
            ]}
          />
        </div>
        <div className="rounded-md border border-line bg-surface p-3">
          <div className="mb-2 text-xs font-medium text-ink-2">Treffer (Verbindungen)</div>
          <TimeChart data={hits} hours={hours} format={(v) => fmtNumber(Math.round(v))} height={180} series={[{ key: "hits", label: "Treffer", slot: 1 }]} />
        </div>
      </div>
      <div className="grid gap-3 md:grid-cols-3">
        <TopList fwId={fwId} ruleId={ruleId} hours={hours} by="src_ip" title="Top-Quellen" />
        <TopList fwId={fwId} ruleId={ruleId} hours={hours} by="dst_ip" title="Top-Ziele" />
        <TopList fwId={fwId} ruleId={ruleId} hours={hours} by="dst_port" title="Top-Zielports" />
      </div>
    </div>
  );
}
