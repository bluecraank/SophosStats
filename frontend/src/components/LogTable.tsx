import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { ChevronRight, Equal, EqualNot, Loader2, Route, Search, X } from "lucide-react";
import { Fragment, useMemo, useState, type MouseEvent, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api } from "@/lib/api";
import { fmtBytes, fmtDate } from "@/lib/format";
import type { Firewall, LogItem } from "@/lib/types";
import { cn } from "@/lib/utils";
import { AddFilter, FIELDS, FilterChip, NEGATE, RAW_TO_COLUMN, type LogFilterValue } from "./LogFilters";
import { Empty, ErrorBox, Loading, Pill, RANGES } from "./ui";

interface LogPage {
  items: LogItem[];
  next: { before_time: string; before_id: number } | null;
}

export interface LogFilter {
  firewall_id?: number;
  rule_id?: number;
}

function parseFilters(raw: string | null): LogFilterValue[] {
  if (!raw) return [];
  try {
    const v = JSON.parse(raw);
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}

/** Wert, der per Klick zum Filter wird (Strg/⌘+Klick = ausschließen). */
function Filterable({
  field,
  value,
  onFilter,
  children,
  className,
}: {
  field: string;
  value: string | number | null | undefined;
  onFilter: (f: LogFilterValue) => void;
  children?: ReactNode;
  className?: string;
}) {
  if (value == null || value === "") return null;
  const click = (e: MouseEvent) => {
    e.stopPropagation();
    onFilter({ field, op: e.ctrlKey || e.metaKey ? "ne" : "eq", value: String(value) });
  };
  return (
    <button
      type="button"
      onClick={click}
      title="Klick: danach filtern · Strg+Klick: ausschließen"
      className={cn("rounded-sm text-left decoration-primary/60 underline-offset-2 hover:text-primary hover:underline", className)}
    >
      {children ?? value}
    </button>
  );
}

function Details({ log, onFilter }: { log: LogItem; onFilter: (f: LogFilterValue) => void }) {
  const entries = Object.entries(log.fields).filter(([, v]) => v !== "");
  return (
    <div className="space-y-3 bg-muted/30 px-4 py-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        {log.message ? <p className="text-sm">{log.message}</p> : <span />}
        {log.src_ip && log.dst_ip && (
          <Button variant="outline" size="sm" asChild>
            <Link
              to={`/cross-site?${new URLSearchParams({
                src: log.src_ip,
                dst: log.dst_ip,
                ...(log.dst_port ? { port: String(log.dst_port) } : {}),
                ...(log.protocol ? { proto: log.protocol } : {}),
                t: log.time,
              })}`}
            >
              <Route /> Pfad über alle Firewalls verfolgen
            </Link>
          </Button>
        )}
      </div>
      <dl className="grid gap-x-6 gap-y-0.5 font-mono text-xs sm:grid-cols-2 xl:grid-cols-3">
        {entries.map(([k, v]) => {
          const field = RAW_TO_COLUMN[k] ?? k;
          return (
            <div key={k} className="group flex items-center gap-2 overflow-hidden rounded px-1 hover:bg-muted">
              <dt className="shrink-0 text-muted-foreground">{k}</dt>
              <dd className="min-w-0 flex-1 truncate" title={v}>{v}</dd>
              <span className="flex shrink-0 opacity-0 transition-opacity group-hover:opacity-100">
                <button className="rounded p-0.5 hover:bg-primary/15 hover:text-primary" title="Danach filtern" onClick={() => onFilter({ field, op: "eq", value: v })}>
                  <Equal className="size-3.5" />
                </button>
                <button className="rounded p-0.5 hover:bg-critical/15 hover:text-critical" title="Ausschließen" onClick={() => onFilter({ field, op: "ne", value: v })}>
                  <EqualNot className="size-3.5" />
                </button>
              </span>
            </div>
          );
        })}
      </dl>
    </div>
  );
}

export function LogTable({ fixed = {}, firewalls }: { fixed?: LogFilter; firewalls?: Firewall[] }) {
  // Suchzustand in der URL (teilbar, Lesezeichen) – andere Parameter wie ?tab bleiben erhalten
  const [params, setParams] = useSearchParams();
  const update = (changes: Record<string, string | null>) =>
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        for (const [k, v] of Object.entries(changes)) {
          if (v == null || v === "") next.delete(k);
          else next.set(k, v);
        }
        return next;
      },
      { replace: true },
    );

  const filters = useMemo(() => parseFilters(params.get("lf")), [params]);
  const search = params.get("lq") ?? "";
  const hours = Number(params.get("lh") ?? 24);
  const logType = params.get("lt") ?? "";
  const firewallId = fixed.firewall_id ?? (params.get("fw") ? Number(params.get("fw")) : undefined);
  const [q, setQ] = useState(search);
  const [expanded, setExpanded] = useState<number | null>(null);

  const setFilters = (list: LogFilterValue[]) => update({ lf: list.length ? JSON.stringify(list) : null });
  const addFilter = (f: LogFilterValue) => {
    const exists = filters.some((x) => x.field === f.field && x.op === f.op && x.value === f.value);
    if (!exists) setFilters([...filters, f]);
  };

  const facets = useQuery({
    queryKey: ["log-facets", firewallId],
    queryFn: () => api<{ log_types: Record<string, string[]> }>("/api/logs/facets", { params: { firewall_id: firewallId } }),
  });

  const filterJson = filters.length ? JSON.stringify(filters) : undefined;
  const logs = useInfiniteQuery({
    queryKey: ["logs", firewallId, fixed.rule_id, logType, search, hours, filterJson],
    queryFn: ({ pageParam }) =>
      api<LogPage>("/api/logs", {
        params: {
          firewall_id: firewallId,
          rule_id: fixed.rule_id,
          log_type: logType,
          q: search,
          filters: filterJson,
          start: new Date(Date.now() - hours * 3600_000).toISOString().slice(0, 16) + ":00Z",
          ...pageParam,
          limit: 100,
        },
      }),
    initialPageParam: {} as Record<string, string | number>,
    getNextPageParam: (last) => last.next ?? undefined,
    refetchInterval: 30_000,
  });

  const items = logs.data?.pages.flatMap((p) => p.items) ?? [];
  // Feldnamen aus den geladenen Logs als Vorschläge für den Filter-Dialog
  const rawFields = useMemo(() => {
    const keys = new Set<string>();
    for (const l of items.slice(0, 300)) for (const k of Object.keys(l.fields)) if (!FIELDS[k] && !RAW_TO_COLUMN[k]) keys.add(k);
    return [...keys].sort();
  }, [items]);
  const fwName = (id: number | null) => firewalls?.find((f) => f.id === id)?.name ?? id;
  const showFw = !fixed.firewall_id && !!firewalls;
  const cols = showFw ? 9 : 8;

  return (
    <div className="space-y-3">
      <form
        className="flex flex-wrap items-center gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          update({ lq: q.trim() || null });
        }}
      >
        <div className="relative min-w-64 flex-1">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input className="pl-8" placeholder="Volltext: IP, Benutzer, Regel, Meldung … (Enter)" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        {showFw && (
          <Select value={firewallId ? String(firewallId) : "all"} onValueChange={(v) => update({ fw: v === "all" ? null : v })}>
            <SelectTrigger className="w-44"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Alle Firewalls</SelectItem>
              {firewalls!.map((f) => <SelectItem key={f.id} value={String(f.id)}>{f.name}</SelectItem>)}
            </SelectContent>
          </Select>
        )}
        <Select value={logType || "all"} onValueChange={(v) => update({ lt: v === "all" ? null : v })}>
          <SelectTrigger className="w-40"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Alle Log-Typen</SelectItem>
            {Object.keys(facets.data?.log_types ?? {}).map((t) => <SelectItem key={t} value={t}>{t}</SelectItem>)}
          </SelectContent>
        </Select>
        <Select value={String(hours)} onValueChange={(v) => update({ lh: v === "24" ? null : v })}>
          <SelectTrigger className="w-36"><SelectValue /></SelectTrigger>
          <SelectContent>
            {RANGES.map((r) => <SelectItem key={r.hours} value={String(r.hours)}>Letzte {r.label}</SelectItem>)}
          </SelectContent>
        </Select>
        <AddFilter rawFields={rawFields} onAdd={addFilter} />
      </form>

      {(filters.length > 0 || search) && (
        <div className="flex flex-wrap items-center gap-2">
          {search && (
            <FilterChip f={{ field: "Volltext", op: "contains", value: search }} onRemove={() => { setQ(""); update({ lq: null }); }} />
          )}
          {filters.map((f, i) => (
            <FilterChip
              key={`${f.field}-${f.op}-${f.value}-${i}`}
              f={f}
              onRemove={() => setFilters(filters.filter((_, j) => j !== i))}
              onToggle={
                NEGATE[f.op] || Object.values(NEGATE).includes(f.op)
                  ? () => {
                      const inverse = NEGATE[f.op] ?? (Object.entries(NEGATE).find(([, v]) => v === f.op)?.[0] as typeof f.op);
                      setFilters(filters.map((x, j) => (j === i ? { ...x, op: inverse } : x)));
                    }
                  : undefined
              }
            />
          ))}
          <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => { setQ(""); update({ lf: null, lq: null }); }}>
            <X /> Alle entfernen
          </Button>
        </div>
      )}

      <ErrorBox error={logs.error} />
      {logs.isPending ? (
        <Loading />
      ) : items.length === 0 ? (
        <Empty>Keine Logeinträge gefunden</Empty>
      ) : (
        <div className="overflow-x-auto rounded-xl border bg-card">
          <table className="w-full text-sm">
            <thead className="border-b bg-muted/40 text-left text-xs text-muted-foreground">
              <tr>
                <th className="w-6" />
                <th className="px-3 py-2.5 font-medium">Zeit</th>
                {showFw && <th className="px-3 py-2.5 font-medium">Firewall</th>}
                <th className="px-3 py-2.5 font-medium">Typ</th>
                <th className="px-3 py-2.5 font-medium">Regel</th>
                <th className="px-3 py-2.5 font-medium">Quelle</th>
                <th className="px-3 py-2.5 font-medium">Ziel</th>
                <th className="px-3 py-2.5 font-medium">Benutzer</th>
                <th className="px-3 py-2.5 text-right font-medium">Bytes ↑ / ↓</th>
              </tr>
            </thead>
            <tbody>
              {items.map((l) => {
                const denied = l.log_subtype === "Denied" || l.status === "Deny";
                const open = expanded === l.id;
                return (
                  <Fragment key={l.id}>
                    <tr
                      className={cn("cursor-pointer border-t transition-colors hover:bg-muted/40", open && "bg-muted/40")}
                      onClick={() => setExpanded(open ? null : l.id)}
                    >
                      <td className="pl-2 text-muted-foreground">
                        <ChevronRight className={cn("size-4 transition-transform", open && "rotate-90")} />
                      </td>
                      <td className="px-3 py-2 whitespace-nowrap text-muted-foreground tabular-nums">{fmtDate(l.time)}</td>
                      {showFw && <td className="px-3 py-2">{fwName(l.firewall_id)}</td>}
                      <td className="px-3 py-2 whitespace-nowrap">
                        <Filterable
                          field={l.log_subtype ? "log_subtype" : "log_type"}
                          value={l.log_subtype ?? l.log_type}
                          onFilter={addFilter}
                        >
                          <Pill tone={denied ? "critical" : "neutral"}>
                            {l.log_type}
                            {l.log_subtype ? ` · ${l.log_subtype}` : ""}
                          </Pill>
                        </Filterable>
                      </td>
                      <td className="max-w-48 truncate px-3 py-2">
                        <Filterable field="rule_name" value={l.rule_name} onFilter={addFilter} />
                        {!l.rule_name && <Filterable field="rule_id" value={l.rule_id} onFilter={addFilter}>#{l.rule_id}</Filterable>}
                      </td>
                      <td className="px-3 py-2 font-mono text-xs whitespace-nowrap">
                        <Filterable field="src_ip" value={l.src_ip} onFilter={addFilter} />
                        {l.src_port ? <span className="text-muted-foreground">:{l.src_port}</span> : null}
                      </td>
                      <td className="px-3 py-2 font-mono text-xs whitespace-nowrap">
                        <Filterable field="dst_ip" value={l.dst_ip} onFilter={addFilter} />
                        {l.dst_port ? (
                          <Filterable field="dst_port" value={l.dst_port} onFilter={addFilter} className="text-muted-foreground">:{l.dst_port}</Filterable>
                        ) : null}{" "}
                        {l.protocol && <span className="text-muted-foreground/70">{l.protocol}</span>}
                      </td>
                      <td className="max-w-40 truncate px-3 py-2">
                        <Filterable field="user_name" value={l.user_name} onFilter={addFilter} />
                      </td>
                      <td className="px-3 py-2 text-right text-xs whitespace-nowrap tabular-nums">
                        {l.sent_bytes != null || l.recv_bytes != null ? `${fmtBytes(l.sent_bytes)} / ${fmtBytes(l.recv_bytes)}` : ""}
                      </td>
                    </tr>
                    {open && (
                      <tr className="border-t">
                        <td colSpan={cols} className="p-0">
                          <Details log={l} onFilter={addFilter} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span>
          {items.length} Einträge geladen · Klick auf einen Wert filtert, Strg+Klick schließt aus
        </span>
        {logs.hasNextPage && (
          <Button variant="outline" size="sm" onClick={() => logs.fetchNextPage()} disabled={logs.isFetchingNextPage}>
            {logs.isFetchingNextPage && <Loader2 className="animate-spin" />} Ältere laden
          </Button>
        )}
      </div>
    </div>
  );
}
