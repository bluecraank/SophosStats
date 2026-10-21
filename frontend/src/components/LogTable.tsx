import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { Fragment, useState } from "react";
import { api } from "../lib/api";
import { fmtBytes, fmtDate } from "../lib/format";
import type { Firewall, LogItem } from "../lib/types";
import { Empty, ErrorBox, Loading, Pill, RANGES } from "./ui";

interface LogPage {
  items: LogItem[];
  next: { before_time: string; before_id: number } | null;
}

export interface LogFilter {
  firewall_id?: number;
  rule_id?: number;
}

export function LogTable({ fixed = {}, firewalls }: { fixed?: LogFilter; firewalls?: Firewall[] }) {
  const [firewallId, setFirewallId] = useState<number | undefined>(fixed.firewall_id);
  const [logType, setLogType] = useState("");
  const [subtype, setSubtype] = useState("");
  const [q, setQ] = useState("");
  const [search, setSearch] = useState("");
  const [hours, setHours] = useState(24);
  const [expanded, setExpanded] = useState<number | null>(null);

  const facets = useQuery({
    queryKey: ["log-facets", firewallId],
    queryFn: () => api<{ log_types: Record<string, string[]> }>("/api/logs/facets", { params: { firewall_id: firewallId } }),
  });

  const params = {
    firewall_id: firewallId,
    rule_id: fixed.rule_id,
    log_type: logType,
    log_subtype: subtype,
    q: search,
    start: new Date(Date.now() - hours * 3600_000).toISOString().slice(0, 16) + ":00Z",
  };
  const logs = useInfiniteQuery({
    queryKey: ["logs", params.firewall_id, params.rule_id, logType, subtype, search, hours],
    queryFn: ({ pageParam }) => api<LogPage>("/api/logs", { params: { ...params, ...pageParam, limit: 100 } }),
    initialPageParam: {} as Record<string, string | number>,
    getNextPageParam: (last) => last.next ?? undefined,
    refetchInterval: 30_000,
  });

  const items = logs.data?.pages.flatMap((p) => p.items) ?? [];
  const fwName = (id: number | null) => firewalls?.find((f) => f.id === id)?.name ?? id;
  const showFw = !fixed.firewall_id && firewalls;

  return (
    <div className="space-y-3">
      <form
        className="flex flex-wrap items-end gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          setSearch(q.trim());
        }}
      >
        {showFw && (
          <select className="input w-auto" value={firewallId ?? ""} onChange={(e) => setFirewallId(e.target.value ? Number(e.target.value) : undefined)} aria-label="Firewall">
            <option value="">Alle Firewalls</option>
            {firewalls.map((f) => (
              <option key={f.id} value={f.id}>{f.name}</option>
            ))}
          </select>
        )}
        <select className="input w-auto" value={logType} onChange={(e) => { setLogType(e.target.value); setSubtype(""); }} aria-label="Log-Typ">
          <option value="">Alle Typen</option>
          {Object.keys(facets.data?.log_types ?? {}).map((t) => (
            <option key={t}>{t}</option>
          ))}
        </select>
        {logType && (facets.data?.log_types[logType]?.length ?? 0) > 0 && (
          <select className="input w-auto" value={subtype} onChange={(e) => setSubtype(e.target.value)} aria-label="Untertyp">
            <option value="">Alle Untertypen</option>
            {facets.data?.log_types[logType].map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        )}
        <select className="input w-auto" value={hours} onChange={(e) => setHours(Number(e.target.value))} aria-label="Zeitraum">
          {RANGES.map((r) => (
            <option key={r.hours} value={r.hours}>Letzte {r.label}</option>
          ))}
        </select>
        <input className="input w-64" placeholder="Suche: IP, Benutzer, Regel, Text" value={q} onChange={(e) => setQ(e.target.value)} />
        <button className="btn-secondary">Suchen</button>
      </form>

      <ErrorBox error={logs.error} />
      {logs.isPending ? (
        <Loading />
      ) : items.length === 0 ? (
        <Empty>Keine Logeinträge gefunden</Empty>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border bg-card">
          <table className="w-full text-sm">
            <thead className="bg-muted text-left text-xs text-muted-foreground">
              <tr>
                <th className="px-3 py-2 font-medium">Zeit</th>
                {showFw && <th className="px-3 py-2 font-medium">Firewall</th>}
                <th className="px-3 py-2 font-medium">Typ</th>
                <th className="px-3 py-2 font-medium">Regel</th>
                <th className="px-3 py-2 font-medium">Quelle</th>
                <th className="px-3 py-2 font-medium">Ziel</th>
                <th className="px-3 py-2 font-medium">Benutzer</th>
                <th className="px-3 py-2 text-right font-medium">Bytes ↑/↓</th>
              </tr>
            </thead>
            <tbody>
              {items.map((l) => (
                <Fragment key={l.id}>
                  <tr className="cursor-pointer border-t border-border hover:bg-muted" onClick={() => setExpanded(expanded === l.id ? null : l.id)}>
                    <td className="whitespace-nowrap px-3 py-1.5 text-muted-foreground">{fmtDate(l.time)}</td>
                    {showFw && <td className="px-3 py-1.5">{fwName(l.firewall_id)}</td>}
                    <td className="whitespace-nowrap px-3 py-1.5">
                      <Pill tone={l.log_subtype === "Denied" || l.status === "Deny" ? "critical" : "neutral"}>
                        {l.log_type}
                        {l.log_subtype ? ` · ${l.log_subtype}` : ""}
                      </Pill>
                    </td>
                    <td className="max-w-48 truncate px-3 py-1.5">{l.rule_name ?? (l.rule_id != null ? `#${l.rule_id}` : "")}</td>
                    <td className="whitespace-nowrap px-3 py-1.5 font-mono text-xs">{l.src_ip}{l.src_port ? `:${l.src_port}` : ""}</td>
                    <td className="whitespace-nowrap px-3 py-1.5 font-mono text-xs">
                      {l.dst_ip}{l.dst_port ? `:${l.dst_port}` : ""} {l.protocol && <span className="text-muted-foreground/70">{l.protocol}</span>}
                    </td>
                    <td className="max-w-40 truncate px-3 py-1.5">{l.user_name}</td>
                    <td className="whitespace-nowrap px-3 py-1.5 text-right text-xs">
                      {l.sent_bytes != null || l.recv_bytes != null ? `${fmtBytes(l.sent_bytes)} / ${fmtBytes(l.recv_bytes)}` : ""}
                    </td>
                  </tr>
                  {expanded === l.id && (
                    <tr className="border-t border-border bg-muted">
                      <td colSpan={showFw ? 8 : 7} className="px-3 py-2">
                        {l.message && <p className="mb-2 text-sm">{l.message}</p>}
                        <dl className="grid gap-x-4 gap-y-0.5 font-mono text-xs sm:grid-cols-2 lg:grid-cols-3">
                          {Object.entries(l.fields).map(([k, v]) => (
                            <div key={k} className="flex gap-2 overflow-hidden">
                              <dt className="shrink-0 text-muted-foreground/70">{k}</dt>
                              <dd className="truncate" title={v}>{v}</dd>
                            </div>
                          ))}
                        </dl>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {logs.hasNextPage && (
        <button className="btn-secondary" onClick={() => logs.fetchNextPage()} disabled={logs.isFetchingNextPage}>
          {logs.isFetchingNextPage ? "Lade …" : "Ältere laden"}
        </button>
      )}
    </div>
  );
}
