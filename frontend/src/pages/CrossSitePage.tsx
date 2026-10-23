import { useQuery } from "@tanstack/react-query";
import {
  ArrowRight,
  CircleCheck,
  CircleDashed,
  CircleHelp,
  CircleX,
  Monitor,
  RefreshCw,
  Route,
  Search,
  Server,
  ShieldAlert,
  TriangleAlert,
  type LucideIcon,
} from "lucide-react";
import { useState, type FormEvent } from "react";
import { useSearchParams } from "react-router";
import { Card, Empty, ErrorBox, Loading, PageHeader, Pill, RANGES } from "@/components/ui";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api } from "@/lib/api";
import { fmtDate, fmtNumber, fmtRelative } from "@/lib/format";
import { cn } from "@/lib/utils";

interface SiteNet {
  cidr: string;
  interface: string | null;
  zone: string | null;
  source: "auto" | "manual";
  conflict: boolean;
}
interface Site {
  firewall_id: number;
  name: string;
  networks: SiteNet[];
}
interface HopInfo {
  firewall_id: number;
  name: string;
  role: "origin" | "destination" | "transit" | "single";
  decision: "allowed" | "denied" | "mixed" | "not_seen";
  allowed: number;
  denied: number;
  allow_rules: string[];
  deny_rules: string[];
}
interface Trace {
  query: { src_ip: string; dst_ip: string; dst_port: number | null; protocol: string | null; start: string; end: string };
  src_site: { name: string } | null;
  dst_site: { name: string } | null;
  hops: HopInfo[];
  verdict: { status: "ok" | "blocked" | "missing_rule" | "incomplete" | "unknown"; text: string };
  timeline: { firewall: string; rule: string | null; subtype: string | null; status: string | null; count: number; first: string; last: string }[];
}
interface BlockedItem {
  src_ip: string;
  dst_ip: string;
  dst_port: number | null;
  protocol: string | null;
  src_site: string;
  dst_site: string;
  attempts: number;
  last: string;
  blocked: { firewall_id: number; name: string; rule: string }[];
  allowed: { firewall_id: number; name: string; rule: string }[];
  blocked_at: "Ausgang" | "Eingang";
  fix_on: { firewall_id: number; name: string };
}

const DECISION: Record<HopInfo["decision"], { label: string; icon: LucideIcon; cls: string }> = {
  allowed: { label: "erlaubt", icon: CircleCheck, cls: "border-good/40 bg-good/10 text-good" },
  denied: { label: "blockiert", icon: CircleX, cls: "border-critical/50 bg-critical/10 text-critical" },
  mixed: { label: "teils blockiert", icon: TriangleAlert, cls: "border-warning/50 bg-warning/10 text-warning" },
  not_seen: { label: "nicht gesehen", icon: CircleDashed, cls: "border-dashed text-muted-foreground" },
};
const ROLE: Record<HopInfo["role"], string> = {
  origin: "Quell-Standort",
  destination: "Ziel-Standort",
  transit: "weitere Firewall",
  single: "Standort",
};
const VERDICT: Record<Trace["verdict"]["status"], { title: string; icon: LucideIcon; cls: string }> = {
  ok: { title: "Verbindung erlaubt", icon: CircleCheck, cls: "border-good/40 bg-good/5 [&>svg]:text-good" },
  blocked: { title: "Verbindung blockiert", icon: CircleX, cls: "border-critical/40 bg-critical/5 [&>svg]:text-critical" },
  missing_rule: { title: "Regel fehlt", icon: ShieldAlert, cls: "border-critical/40 bg-critical/5 [&>svg]:text-critical" },
  incomplete: { title: "Unvollständig", icon: TriangleAlert, cls: "border-warning/40 bg-warning/5 [&>svg]:text-warning" },
  unknown: { title: "Keine Daten", icon: CircleHelp, cls: "" },
};

export interface TraceParams {
  src: string;
  dst: string;
  port?: string;
  proto?: string;
  t?: string;
}

function Endpoint({ ip, site, label }: { ip: string; site: string | null | undefined; label: string }) {
  return (
    <div className="flex w-40 shrink-0 flex-col items-center gap-1.5 rounded-xl border bg-card px-3 py-3 text-center">
      <Monitor className="size-5 text-muted-foreground" />
      <div className="text-[11px] text-muted-foreground uppercase">{label}</div>
      <div className="font-mono text-sm font-medium">{ip}</div>
      <div className="text-xs text-muted-foreground">{site ? `Standort ${site}` : "Standort unbekannt"}</div>
    </div>
  );
}

function HopCard({ h }: { h: HopInfo }) {
  const d = DECISION[h.decision];
  return (
    <div className={cn("flex w-56 shrink-0 flex-col gap-2 rounded-xl border-2 bg-card p-3", d.cls.split(" ").filter((c) => c.startsWith("border")).join(" "))}>
      <div className="flex items-center gap-2">
        <Server className="size-4 text-muted-foreground" />
        <span className="font-semibold">{h.name}</span>
      </div>
      <div className="text-[11px] text-muted-foreground uppercase">{ROLE[h.role]}</div>
      <span className={cn("inline-flex w-fit items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium", d.cls)}>
        <d.icon className="size-3.5" /> {d.label}
      </span>
      {h.allow_rules.length > 0 && (
        <div className="text-xs"><span className="text-muted-foreground">Erlaubt durch: </span>{h.allow_rules.join(", ")} <span className="text-muted-foreground">({fmtNumber(h.allowed)}×)</span></div>
      )}
      {h.deny_rules.length > 0 && (
        <div className="text-xs"><span className="text-muted-foreground">Blockiert durch: </span>{h.deny_rules.join(", ")} <span className="text-muted-foreground">({fmtNumber(h.denied)}×)</span></div>
      )}
      {h.decision === "not_seen" && <div className="text-xs text-muted-foreground">Keine Logs zu dieser Verbindung</div>}
    </div>
  );
}

const Arrow = () => <ArrowRight className="size-5 shrink-0 text-muted-foreground" />;

export function PathTrace({ p }: { p: TraceParams }) {
  const q = useQuery({
    queryKey: ["trace", p],
    queryFn: () =>
      api<Trace>("/api/trace", {
        params: { src_ip: p.src, dst_ip: p.dst, dst_port: p.port, protocol: p.proto, time: p.t, hours: p.t ? undefined : 24 },
      }),
  });
  if (q.isPending) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const t = q.data;
  const v = VERDICT[t.verdict.status];
  return (
    <div className="space-y-4">
      <Alert className={v.cls}>
        <v.icon />
        <AlertTitle>{v.title}</AlertTitle>
        <AlertDescription>{t.verdict.text}</AlertDescription>
      </Alert>
      <div className="flex items-center gap-3 overflow-x-auto pb-2">
        <Endpoint ip={t.query.src_ip} site={t.src_site?.name} label="Quelle" />
        {t.hops.map((h) => (
          <div key={h.firewall_id} className="flex items-center gap-3">
            <Arrow />
            <HopCard h={h} />
          </div>
        ))}
        <Arrow />
        <Endpoint ip={t.query.dst_ip} site={t.dst_site?.name} label={`Ziel ${t.query.protocol ?? ""}${t.query.dst_port ? `/${t.query.dst_port}` : ""}`} />
      </div>
      <div className="text-xs text-muted-foreground">
        Zeitfenster {fmtDate(t.query.start)} – {fmtDate(t.query.end)}
      </div>
      {t.timeline.length > 0 && (
        <table className="w-full text-sm">
          <thead className="text-left text-xs text-muted-foreground">
            <tr>
              <th className="py-1.5 font-medium">Erstmals</th>
              <th className="py-1.5 font-medium">Firewall</th>
              <th className="py-1.5 font-medium">Entscheidung</th>
              <th className="py-1.5 font-medium">Regel</th>
              <th className="py-1.5 text-right font-medium">Anzahl</th>
            </tr>
          </thead>
          <tbody>
            {t.timeline.map((e, i) => {
              const denied = e.subtype === "Denied" || ["deny", "drop"].includes((e.status ?? "").toLowerCase());
              return (
                <tr key={i} className="border-t">
                  <td className="py-1.5 text-muted-foreground tabular-nums">{fmtDate(e.first)}</td>
                  <td className="py-1.5">{e.firewall}</td>
                  <td className="py-1.5"><Pill tone={denied ? "critical" : "good"}>{denied ? "blockiert" : "erlaubt"}</Pill></td>
                  <td className="py-1.5">{e.rule ?? "–"}</td>
                  <td className="py-1.5 text-right tabular-nums">{fmtNumber(e.count)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}

function SitesCard() {
  const q = useQuery({ queryKey: ["sites"], queryFn: () => api<Site[]>("/api/sites") });
  return (
    <Card title="Standorte & Netze" icon={Server}>
      <ErrorBox error={q.error} />
      {q.isPending ? (
        <Loading />
      ) : (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {q.data?.map((s) => (
            <div key={s.firewall_id} className="rounded-lg border p-3">
              <div className="mb-2 font-medium">{s.name}</div>
              {s.networks.length === 0 ? (
                <div className="text-xs text-warning">Keine Netze erkannt – unter „Firewalls verwalten“ ergänzen</div>
              ) : (
                <div className="flex flex-wrap gap-1.5">
                  {s.networks.map((n) => (
                    <Badge
                      key={n.cidr}
                      variant="outline"
                      className={cn("font-mono font-normal", n.conflict && "border-warning/50 text-warning line-through")}
                      title={
                        n.conflict
                          ? "Netz kommt auf mehreren Firewalls vor – nicht eindeutig, wird ignoriert"
                          : n.source === "auto"
                            ? `automatisch: ${n.interface}${n.zone ? ` (Zone ${n.zone})` : ""}`
                            : "manuell eingetragen"
                      }
                    >
                      {n.cidr}
                      {n.source === "manual" && <span className="ml-1 font-sans text-[10px] text-muted-foreground">manuell</span>}
                    </Badge>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
      <p className="mt-3 text-xs text-muted-foreground">
        Netze werden aus den Interfaces/VLANs (LAN-/DMZ-Zonen, private Netze) erkannt. Tunnel-Transfernetze und WAN werden ignoriert.
        Fehlende Netze unter <em>Firewalls verwalten → Standort-Netze</em> ergänzen.
      </p>
    </Card>
  );
}

function BlockedTable({ onTrace }: { onTrace: (p: TraceParams) => void }) {
  const [hours, setHours] = useState(24);
  const q = useQuery({
    queryKey: ["cross-blocked", hours],
    queryFn: () => api<{ items: BlockedItem[]; total: number }>("/api/cross-site/blocked", { params: { hours } }),
    // Teure Gruppierung über alle abgelehnten Verbindungen – nur auf Anforderung neu laden
    staleTime: 5 * 60_000,
  });
  return (
    <Card
      title="Blockiert zwischen Standorten"
      icon={ShieldAlert}
      actions={
        <div className="flex items-center gap-2">
        <Button variant="outline" size="sm" onClick={() => q.refetch()} disabled={q.isFetching} title="Neu laden">
          <RefreshCw className={q.isFetching ? "animate-spin" : ""} />
        </Button>
        <Select value={String(hours)} onValueChange={(v) => setHours(Number(v))}>
          <SelectTrigger size="sm" className="w-36"><SelectValue /></SelectTrigger>
          <SelectContent>
            {RANGES.map((r) => <SelectItem key={r.hours} value={String(r.hours)}>Letzte {r.label}</SelectItem>)}
          </SelectContent>
        </Select>
        </div>
      }
    >
      <ErrorBox error={q.error} />
      {q.isPending ? (
        <Loading />
      ) : !q.data || q.data.items.length === 0 ? (
        <Empty>Keine blockierten Verbindungen zwischen Standorten im Zeitraum.</Empty>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-xs text-muted-foreground">
              <tr>
                <th className="py-2 pr-3 font-medium">Quelle</th>
                <th className="py-2 pr-3 font-medium">Ziel</th>
                <th className="py-2 pr-3 font-medium">Dienst</th>
                <th className="py-2 pr-3 text-right font-medium">Versuche</th>
                <th className="py-2 pr-3 font-medium">Blockiert</th>
                <th className="py-2 pr-3 font-medium">Erlaubt auf</th>
                <th className="py-2 pr-3 font-medium">Handlungsbedarf</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {q.data.items.map((it) => (
                <tr key={`${it.src_ip}-${it.dst_ip}-${it.dst_port}-${it.protocol}`} className="border-t align-top">
                  <td className="py-2 pr-3"><div className="font-mono">{it.src_ip}</div><div className="text-xs text-muted-foreground">{it.src_site}</div></td>
                  <td className="py-2 pr-3"><div className="font-mono">{it.dst_ip}</div><div className="text-xs text-muted-foreground">{it.dst_site}</div></td>
                  <td className="py-2 pr-3 font-mono text-xs whitespace-nowrap">{it.protocol ?? "?"}/{it.dst_port ?? "–"}</td>
                  <td className="py-2 pr-3 text-right tabular-nums">
                    {fmtNumber(it.attempts)}
                    <div className="text-xs text-muted-foreground">{fmtRelative(it.last)}</div>
                  </td>
                  <td className="py-2 pr-3">
                    {it.blocked.map((b) => (
                      <div key={b.firewall_id} className="text-xs"><span className="font-medium text-critical">{b.name}</span> · {b.rule}</div>
                    ))}
                    <div className="text-[11px] text-muted-foreground">am {it.blocked_at}</div>
                  </td>
                  <td className="py-2 pr-3">
                    {it.allowed.length === 0 ? <span className="text-xs text-muted-foreground">–</span> : it.allowed.map((a) => (
                      <div key={a.firewall_id} className="text-xs"><span className="font-medium text-good">{a.name}</span> · {a.rule}</div>
                    ))}
                  </td>
                  <td className="py-2 pr-3 text-xs">
                    {it.allowed.length > 0
                      ? <>Regel fehlt auf <strong>{it.fix_on.name}</strong></>
                      : <>Auf <strong>{it.fix_on.name}</strong> blockiert{it.blocked_at === "Ausgang" ? ` – ${it.dst_site} nie erreicht` : ""}</>}
                  </td>
                  <td className="py-2">
                    <Button size="sm" variant="outline" onClick={() => onTrace({ src: it.src_ip, dst: it.dst_ip, port: it.dst_port ? String(it.dst_port) : undefined, proto: it.protocol ?? undefined })}>
                      <Route /> Pfad
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {q.data.total > q.data.items.length && (
            <p className="mt-2 text-xs text-muted-foreground">{q.data.items.length} von {q.data.total} Verbindungen (nach Versuchen sortiert)</p>
          )}
        </div>
      )}
    </Card>
  );
}

export function CrossSitePage() {
  const [params, setParams] = useSearchParams();
  const current: TraceParams | null = params.get("src") && params.get("dst")
    ? { src: params.get("src")!, dst: params.get("dst")!, port: params.get("port") ?? undefined, proto: params.get("proto") ?? undefined, t: params.get("t") ?? undefined }
    : null;
  const [form, setForm] = useState({ src: current?.src ?? "", dst: current?.dst ?? "", port: current?.port ?? "", proto: current?.proto ?? "" });

  const showTrace = (p: TraceParams) => {
    const next = new URLSearchParams();
    next.set("src", p.src);
    next.set("dst", p.dst);
    if (p.port) next.set("port", p.port);
    if (p.proto) next.set("proto", p.proto);
    if (p.t) next.set("t", p.t);
    setParams(next);
    setForm({ src: p.src, dst: p.dst, port: p.port ?? "", proto: p.proto ?? "" });
    window.scrollTo({ top: 0, behavior: "smooth" });
  };
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (form.src && form.dst) showTrace({ src: form.src.trim(), dst: form.dst.trim(), port: form.port.trim() || undefined, proto: form.proto || undefined });
  };

  return (
    <div className="space-y-5">
      <PageHeader
        title="Standortübergreifend"
        description="Verbindungen über mehrere Firewalls verfolgen – wo wird blockiert, wo fehlt die Regel?"
      />
      <Card title="Pfad verfolgen" icon={Route}>
        <form onSubmit={submit} className="flex flex-wrap items-end gap-2">
          <Input className="w-44 font-mono" placeholder="Quell-IP" value={form.src} onChange={(e) => setForm({ ...form, src: e.target.value })} required />
          <ArrowRight className="mb-2.5 size-4 text-muted-foreground" />
          <Input className="w-44 font-mono" placeholder="Ziel-IP" value={form.dst} onChange={(e) => setForm({ ...form, dst: e.target.value })} required />
          <Input className="w-28 font-mono" placeholder="Port" inputMode="numeric" value={form.port} onChange={(e) => setForm({ ...form, port: e.target.value.replace(/\D/g, "") })} />
          <Select value={form.proto || "any"} onValueChange={(v) => setForm({ ...form, proto: v === "any" ? "" : v })}>
            <SelectTrigger className="w-28"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="any">Protokoll</SelectItem>
              <SelectItem value="TCP">TCP</SelectItem>
              <SelectItem value="UDP">UDP</SelectItem>
              <SelectItem value="ICMP">ICMP</SelectItem>
            </SelectContent>
          </Select>
          <Button><Search /> Verfolgen</Button>
          {current?.t && <span className="text-xs text-muted-foreground">Zeitfenster um {fmtDate(current.t)}</span>}
        </form>
        {current && (
          <div className="mt-5">
            <PathTrace p={current} />
          </div>
        )}
      </Card>
      <BlockedTable onTrace={showTrace} />
      <SitesCard />
    </div>
  );
}
