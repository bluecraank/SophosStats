import { useQuery } from "@tanstack/react-query";
import {
  ArrowRight,
  CircleCheck,
  CircleHelp,
  CircleX,
  Globe,
  Info,
  Monitor,
  Route,
  SearchCheck,
  Server,
  Stethoscope,
  type LucideIcon,
} from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router";
import { Card, ErrorBox, Loading, PageHeader, Pill } from "@/components/ui";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { HostInput } from "@/components/HostInput";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

type Result = "yes" | "no" | "unknown";
interface Check {
  criterion: string;
  result: Result;
  detail: string;
}
interface RuleRef {
  name: string;
  position: number;
  action: string | null;
  checks?: Check[];
}
interface Hop {
  firewall_id: number;
  name: string;
  role: string;
  src_zone: string | null;
  dst_zone: string | null;
  link_zone: { zone: string | null; source: string };
  decision: "allow" | "deny" | "unknown";
  rule: RuleRef | null;
  checks: Check[];
  possible_before: RuleRef[];
  near_misses: RuleRef[];
  rule_count: number;
}
interface Loc {
  name: string;
  cidr: string;
  zone: string | null;
}
interface ServiceRef {
  label: string;
  protocol: string;
  port: number | null;
}
interface Verdict {
  status: "allow" | "deny" | "unknown";
  text: string;
}
interface Response {
  mode: "path";
  query: { source: string; destination: string; dst_ip: string; fqdn: string | null; resolved: string[]; service: ServiceRef };
  src: Loc | null;
  dst: Loc | null;
  hops: Hop[];
  verdict: Verdict;
  notes: string[];
  observed: { verdict: { status: string; text: string } } | null;
}
interface ReachRule extends RuleRef {
  certain: boolean;
  checks: Check[];
  source_zones: string[];
  source_networks: string[];
  destination_zones: string[];
  destination_networks: string[];
  services: string[];
}
interface ReachFirewall {
  firewall_id: number;
  name: string;
  role: string;
  zone: string | null;
  link_zone: { zone: string | null; source: string };
  rules: ReachRule[];
  rule_count: number;
}
interface ReachResponse {
  mode: "reach";
  query: { given: string; ip: string; name: string | null; resolved: string[]; service: ServiceRef };
  anchor: Loc | null;
  firewalls: ReachFirewall[];
  verdict: Verdict;
  notes: string[];
}
type Answer = Response | ReachResponse;

const DECISION: Record<Hop["decision"], { label: string; icon: LucideIcon; cls: string; border: string }> = {
  allow: { label: "erlaubt", icon: CircleCheck, cls: "border-good/40 bg-good/10 text-good", border: "border-good/50" },
  deny: { label: "blockiert", icon: CircleX, cls: "border-critical/50 bg-critical/10 text-critical", border: "border-critical/60" },
  unknown: { label: "unsicher", icon: CircleHelp, cls: "border-warning/50 bg-warning/10 text-warning", border: "border-warning/60" },
};
const VERDICT = {
  allow: { title: "Verbindung wäre erlaubt", cls: "border-good/40 bg-good/5 [&>svg]:text-good", icon: CircleCheck },
  deny: { title: "Verbindung würde blockiert", cls: "border-critical/40 bg-critical/5 [&>svg]:text-critical", icon: CircleX },
  unknown: { title: "Nicht eindeutig bestimmbar", cls: "border-warning/40 bg-warning/5 [&>svg]:text-warning", icon: CircleHelp },
};
const REACH_TITLE = {
  allow: "Erlaubende Regeln gefunden",
  deny: "Keine erlaubende Regel",
  unknown: "Nicht eindeutig bestimmbar",
};
const MARK: Record<Result, { icon: LucideIcon; cls: string }> = {
  yes: { icon: CircleCheck, cls: "text-good" },
  no: { icon: CircleX, cls: "text-critical" },
  unknown: { icon: CircleHelp, cls: "text-warning" },
};

function Checks({ checks }: { checks: Check[] }) {
  return (
    <ul className="space-y-1 text-xs">
      {checks.map((c) => {
        const m = MARK[c.result];
        return (
          <li key={c.criterion} className="flex items-start gap-2">
            <m.icon className={cn("mt-0.5 size-3.5 shrink-0", m.cls)} />
            <span className="w-20 shrink-0 text-muted-foreground">{c.criterion}</span>
            <span className="min-w-0 break-words">{c.detail || "–"}</span>
          </li>
        );
      })}
    </ul>
  );
}

function RuleBox({ r, tone }: { r: RuleRef; tone: "near" | "possible" }) {
  return (
    <div className={cn("rounded-lg border p-3", tone === "near" ? "border-primary/30 bg-primary/5" : "border-warning/30 bg-warning/5")}>
      <div className="mb-2 flex items-center gap-2 text-sm">
        <span className="text-muted-foreground">#{r.position + 1}</span>
        <span className="font-medium">{r.name}</span>
        <Pill tone={r.action === "Accept" ? "good" : "critical"}>{r.action ?? "–"}</Pill>
      </div>
      {r.checks && <Checks checks={r.checks} />}
    </div>
  );
}

function Endpoint({ label, value, loc, icon: Icon }: { label: string; value: string; loc: Loc | null; icon: LucideIcon }) {
  return (
    <div className="flex w-48 shrink-0 flex-col items-center gap-1 rounded-xl border bg-card px-3 py-3 text-center">
      <Icon className="size-5 text-muted-foreground" />
      <div className="text-[11px] text-muted-foreground uppercase">{label}</div>
      <div className="font-mono text-sm font-medium break-all">{value}</div>
      <div className="text-xs text-muted-foreground">
        {loc ? `${loc.name} · ${loc.cidr}${loc.zone ? ` · Zone ${loc.zone}` : ""}` : "Internet / unbekannt"}
      </div>
    </div>
  );
}

function HopCard({ h }: { h: Hop }) {
  const d = DECISION[h.decision];
  return (
    <div className={cn("flex w-72 shrink-0 flex-col gap-2 rounded-xl border-2 bg-card p-3", d.border)}>
      <div className="flex items-center gap-2">
        <Server className="size-4 text-muted-foreground" />
        <span className="font-semibold">{h.name}</span>
      </div>
      <div className="text-[11px] text-muted-foreground uppercase">{h.role}</div>
      <div className="text-xs">
        Zone <strong>{h.src_zone ?? "?"}</strong> → <strong>{h.dst_zone ?? "?"}</strong>
      </div>
      <span className={cn("inline-flex w-fit items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium", d.cls)}>
        <d.icon className="size-3.5" /> {d.label}
      </span>
      <div className="text-xs">
        {h.rule ? (
          <>Regel <strong>#{h.rule.position + 1} {h.rule.name}</strong></>
        ) : h.decision === "deny" ? (
          <>Keine passende Regel → <strong>Default Drop</strong></>
        ) : (
          <>Unsichere Regel vor einer Entscheidung</>
        )}
      </div>
    </div>
  );
}

function HopDetails({ h }: { h: Hop }) {
  const linkInfo = h.role.startsWith("Ausgang Richtung") || h.role.startsWith("Eingang von");
  return (
    <Card title={`${h.name} – ${h.role}`} icon={Server}>
      <div className="space-y-4">
        {linkInfo && (
          <p className="text-xs text-muted-foreground">
            Tunnel-Zone zu anderen Standorten: <strong className="text-foreground">{h.link_zone.zone ?? "unbekannt"}</strong> ({h.link_zone.source}).
            {!h.link_zone.zone && " Unter Firewalls verwalten → „Zone zu anderen Standorten“ festlegen."}
          </p>
        )}
        {h.rule && (
          <div>
            <div className="label">Greifende Regel</div>
            <RuleBox r={{ ...h.rule, checks: h.checks }} tone="near" />
          </div>
        )}
        {h.possible_before.length > 0 && (
          <div className="space-y-2">
            <div className="label">Könnte vorher greifen (nicht sicher bestimmbar)</div>
            {h.possible_before.map((r) => <RuleBox key={r.position} r={r} tone="possible" />)}
          </div>
        )}
        {h.decision !== "allow" && h.near_misses.length > 0 && (
          <div className="space-y-2">
            <div className="label">Beinahe-Treffer – erlaubende Regeln, die an genau einem Punkt scheitern</div>
            {h.near_misses.map((r) => <RuleBox key={r.position} r={r} tone="near" />)}
          </div>
        )}
        {h.decision === "deny" && !h.rule && h.near_misses.length === 0 && (
          <p className="text-sm text-muted-foreground">
            Keine erlaubende Regel kommt dieser Verbindung nahe – auf {h.name} wird eine neue Regel benötigt.
          </p>
        )}
        <p className="text-xs text-muted-foreground">{h.rule_count} Regel{h.rule_count === 1 ? "" : "n"} geprüft</p>
      </div>
    </Card>
  );
}

function Names({ items }: { items: string[] }) {
  if (items.length === 0) return <span className="text-muted-foreground">Alle</span>;
  return <span className="break-words">{items.join(", ")}</span>;
}

/** Wer erreicht das Ziel? Regeln je Firewall, die das Ziel enthalten – mit offener Quellseite. */
function ReachResult({ r }: { r: ReachResponse }) {
  const v = VERDICT[r.verdict.status];
  return (
    <div className="space-y-4">
      <Alert className={v.cls}>
        <v.icon />
        <AlertTitle>{REACH_TITLE[r.verdict.status]}</AlertTitle>
        <AlertDescription>{r.verdict.text}</AlertDescription>
      </Alert>

      <div className="flex items-center gap-3 overflow-x-auto pb-2">
        <div className="flex w-48 shrink-0 flex-col items-center gap-1 rounded-xl border border-dashed bg-card px-3 py-3 text-center">
          <Monitor className="size-5 text-muted-foreground" />
          <div className="text-[11px] text-muted-foreground uppercase">Quelle</div>
          <div className="text-sm font-medium">beliebig</div>
          <div className="text-xs text-muted-foreground">laut Regeln unten</div>
        </div>
        <ArrowRight className="size-5 shrink-0 text-muted-foreground" />
        <Endpoint label={`Ziel · ${r.query.service.label}`} value={r.query.name ?? r.query.ip} loc={r.anchor} icon={r.query.name ? Globe : Monitor} />
      </div>

      {r.notes.length > 0 && (
        <ul className="space-y-1 text-xs text-muted-foreground">
          {r.notes.map((n) => (
            <li key={n} className="flex gap-2"><Info className="mt-0.5 size-3.5 shrink-0" />{n}</li>
          ))}
        </ul>
      )}

      {r.firewalls.map((fw) => {
        const linkInfo = fw.role.startsWith("Ausgang Richtung");
        return (
          <Card key={fw.firewall_id} title={`${fw.name} – ${fw.role}`} icon={Server}>
            <div className="space-y-3">
              <p className="text-xs text-muted-foreground">
                Geprüft als Ziel-Zone <strong className="text-foreground">{fw.zone ?? "unbekannt"}</strong>
                {linkInfo && <> (Tunnel-Zone zu anderen Standorten, {fw.link_zone.source})</>}.
                {linkInfo && !fw.link_zone.zone && " Unter Firewalls verwalten → „Zone zu anderen Standorten“ festlegen."}
              </p>
              {fw.rules.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  Keine aktive Regel auf {fw.name} enthält dieses Ziel ({fw.rule_count} Regel{fw.rule_count === 1 ? "" : "n"} geprüft).
                </p>
              ) : (
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-10">#</TableHead>
                        <TableHead>Regel</TableHead>
                        <TableHead>Aktion</TableHead>
                        <TableHead>Quell-Zonen</TableHead>
                        <TableHead>Quell-Netze</TableHead>
                        <TableHead>Dienste</TableHead>
                        <TableHead>Treffer auf Zielseite</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {fw.rules.map((rule) => (
                        <TableRow key={rule.position}>
                          <TableCell className="text-muted-foreground">{rule.position + 1}</TableCell>
                          <TableCell className="font-medium">
                            <Link className="hover:underline" to={`/firewalls/${fw.firewall_id}?tab=rules&rq=${encodeURIComponent(rule.name)}`}>
                              {rule.name}
                            </Link>
                          </TableCell>
                          <TableCell><Pill tone={rule.action === "Accept" ? "good" : "critical"}>{rule.action ?? "–"}</Pill></TableCell>
                          <TableCell><Names items={rule.source_zones} /></TableCell>
                          <TableCell className="max-w-64"><Names items={rule.source_networks} /></TableCell>
                          <TableCell className="max-w-48"><Names items={rule.services} /></TableCell>
                          <TableCell className="min-w-56">
                            {rule.certain ? (
                              <span className="inline-flex items-center gap-1.5 text-xs text-good">
                                <CircleCheck className="size-3.5" /> sicher
                              </span>
                            ) : (
                              <Checks checks={rule.checks.filter((c) => c.result !== "yes")} />
                            )}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </div>
          </Card>
        );
      })}
    </div>
  );
}

function Result({ p }: { p: { source: string; destination: string; service: string } }) {
  const q = useQuery({
    queryKey: ["troubleshoot", p],
    queryFn: () => api<Answer>("/api/troubleshoot", { params: p }),
    staleTime: 60_000,
  });
  if (q.isPending) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  if (q.data.mode === "reach") return <ReachResult r={q.data} />;
  const r = q.data;
  const v = VERDICT[r.verdict.status];
  const traceUrl = `/cross-site?${new URLSearchParams({
    src: r.query.source,
    dst: r.query.dst_ip,
    ...(r.query.service.port ? { port: String(r.query.service.port) } : {}),
    ...(r.query.service.protocol !== "ICMP" ? { proto: r.query.service.protocol } : {}),
  })}`;
  return (
    <div className="space-y-4">
      <Alert className={v.cls}>
        <v.icon />
        <AlertTitle>{v.title}</AlertTitle>
        <AlertDescription>{r.verdict.text}</AlertDescription>
      </Alert>

      <div className="flex items-center gap-3 overflow-x-auto pb-2">
        <Endpoint label="Quelle" value={r.query.source} loc={r.src} icon={Monitor} />
        {r.hops.map((h) => (
          <div key={h.firewall_id} className="flex items-center gap-3">
            <ArrowRight className="size-5 shrink-0 text-muted-foreground" />
            <HopCard h={h} />
          </div>
        ))}
        <ArrowRight className="size-5 shrink-0 text-muted-foreground" />
        <Endpoint label={`Ziel · ${r.query.service.label}`} value={r.query.fqdn ?? r.query.dst_ip} loc={r.dst} icon={r.query.fqdn ? Globe : Monitor} />
      </div>

      {r.observed && (
        <div className="flex flex-wrap items-center gap-2 rounded-lg border bg-muted/30 px-3 py-2 text-sm">
          <Route className="size-4 text-muted-foreground" />
          <span className="text-muted-foreground">Laut Logs (24 h):</span>
          <span>{r.observed.verdict.status === "unknown" ? "keine passenden Logeinträge" : r.observed.verdict.text}</span>
          <Button variant="link" size="sm" className="ml-auto h-auto p-0" asChild>
            <Link to={traceUrl}>Pfad in den Logs ansehen</Link>
          </Button>
        </div>
      )}

      {r.notes.length > 0 && (
        <ul className="space-y-1 text-xs text-muted-foreground">
          {r.notes.map((n) => (
            <li key={n} className="flex gap-2"><Info className="mt-0.5 size-3.5 shrink-0" />{n}</li>
          ))}
        </ul>
      )}

      <div className="grid gap-4 xl:grid-cols-2">
        {r.hops.map((h) => <HopDetails key={h.firewall_id} h={h} />)}
      </div>
    </div>
  );
}

const EXAMPLES = [
  { source: "10.50.10.5", destination: "10.60.10.1", service: "smb" },
  { source: "10.50.10.5", destination: "www.example.com", service: "https" },
  { source: "", destination: "10.60.10.1", service: "" },
];

export function TroubleshootPage() {
  const [params, setParams] = useSearchParams();
  const current = params.get("destination")
    ? { source: params.get("source") ?? "", destination: params.get("destination")!, service: params.get("service") ?? "" }
    : null;
  const [form, setForm] = useState(current ?? { source: "", destination: "", service: "" });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const next: Record<string, string> = { destination: form.destination.trim() };
    if (form.source.trim()) next.source = form.source.trim();
    if (form.service.trim()) next.service = form.service.trim();
    setParams(next);
  };

  return (
    <div className="space-y-5">
      <PageHeader
        title="Fehlersuche"
        description="Prüft anhand der Regelwerke aller beteiligten Firewalls, ob eine Verbindung erlaubt wäre – und woran es scheitert."
      />
      <Card title="Verbindung prüfen" icon={Stethoscope} className="overflow-visible">
        <form onSubmit={submit} className="flex flex-wrap items-end gap-2">
          <label className="space-y-1">
            <span className="label">Quelle (IP oder Hostname, optional)</span>
            <HostInput className="w-56" placeholder="10.50.10.5 oder EDV-" value={form.source} onChange={(v) => setForm({ ...form, source: v })} onPick={(h) => setForm({ ...form, source: h.ip })} />
          </label>
          <ArrowRight className="mb-2.5 size-4 text-muted-foreground" />
          <label className="space-y-1">
            <span className="label">Ziel (IP oder Website)</span>
            <HostInput className="w-64" placeholder="10.60.10.1, Hostname oder Website" value={form.destination} onChange={(v) => setForm({ ...form, destination: v })} onPick={(h) => setForm({ ...form, destination: h.ip })} required />
          </label>
          <label className="space-y-1">
            <span className="label">Dienst{form.source.trim() ? "" : " (optional)"}</span>
            <Input className="w-44 font-mono" placeholder="https, 443, tcp/3389, ping" value={form.service} onChange={(e) => setForm({ ...form, service: e.target.value })} required={!!form.source.trim()} />
          </label>
          <Button><SearchCheck /> Prüfen</Button>
        </form>
        <p className="mt-2 text-xs text-muted-foreground">
          Ohne Quelle wird gezeigt, welche Regeln auf allen Firewalls das Ziel enthalten – also wer es erreichen kann.
        </p>
        {!current && (
          <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
            Beispiele:
            {EXAMPLES.map((ex) => (
              <button key={`${ex.source}>${ex.destination}`} type="button" className="rounded border px-2 py-0.5 font-mono hover:bg-muted" onClick={() => setForm(ex)}>
                {ex.source ? `${ex.source} → ${ex.destination} (${ex.service})` : `Wer erreicht ${ex.destination}?`}
              </button>
            ))}
          </div>
        )}
      </Card>
      {current && <Result p={current} />}
      <p className="text-xs text-muted-foreground">
        Grundlage sind die per XML-API gesicherten Regeln und Objekte sowie die Standort-Netze. NAT, Web-Filter, IPS und
        Anwendungskontrolle werden nicht simuliert; Benutzerregeln und Zeitpläne werden als „unsicher“ markiert.
      </p>
    </div>
  );
}
