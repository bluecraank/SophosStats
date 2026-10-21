import { useQuery } from "@tanstack/react-query";
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  ArrowLeftRight,
  Boxes,
  Cable,
  Crosshair,
  Globe,
  Grid3x3,
  Layers,
  MoreHorizontal,
  Network,
  Plug,
  Search,
  ShieldCheck,
  ShieldX,
  Sparkles,
  Workflow,
  X,
  type LucideIcon,
} from "lucide-react";
import { useMemo, useState, type CSSProperties, type ReactNode } from "react";
import { useSearchParams } from "react-router";
import { Empty, ErrorBox, Loading, Pill } from "@/components/ui";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from "@/components/ui/command";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { ScrollArea } from "@/components/ui/scroll-area";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { api } from "@/lib/api";
import { fmtBytes, fmtNumber, fmtRelative } from "@/lib/format";
import { useTheme } from "@/lib/theme";
import { cn } from "@/lib/utils";

// --- Daten --------------------------------------------------------------------

type NodeType = "zone" | "interface" | "network" | "service" | "rule" | "nat";

interface GNode {
  id: string;
  type: NodeType;
  entity: string | null;
  name: string;
  group: boolean;
  builtin: boolean;
  kind?: string;
  detail?: string;
  data: unknown;
  rule_refs: number;
  action?: string | null;
  enabled?: boolean;
  policy_type?: string | null;
  usage?: { hits?: number; sent_bytes?: number; recv_bytes?: number; last_seen_ever?: string | null; position?: number } | null;
}
interface GEdge {
  source: string;
  target: string;
  kind: string;
}

/** Maximal gezeichnete Regeln bzw. Objekte pro Spalte – darüber wird gefiltert/zusammengefasst. */
const LIMITS = [15, 30, 60];
const COLUMN_LIMIT = 20;
const ANY_ZONE = "Alle Zonen";

const TYPE_META: Record<NodeType, { label: string; plural: string; icon: LucideIcon; tint: string }> = {
  zone: { label: "Zone", plural: "Zonen", icon: Layers, tint: "text-violet-400 bg-violet-500/12" },
  interface: { label: "Interface", plural: "Interfaces", icon: Cable, tint: "text-slate-400 bg-slate-500/15" },
  network: { label: "Netzobjekt", plural: "Netzobjekte", icon: Network, tint: "text-[var(--series-1)] bg-[var(--series-1)]/12" },
  service: { label: "Dienst", plural: "Dienste", icon: Plug, tint: "text-[var(--series-3)] bg-[var(--series-3)]/12" },
  rule: { label: "Firewall-Regel", plural: "Firewall-Regeln", icon: ShieldCheck, tint: "text-good bg-good/12" },
  nat: { label: "NAT-Regel", plural: "NAT-Regeln", icon: ArrowLeftRight, tint: "text-[var(--series-2)] bg-[var(--series-2)]/12" },
};

const EDGE_LABEL: Record<string, string> = {
  source_zone: "Quell-Zone",
  destination_zone: "Ziel-Zone",
  source: "Quelle",
  destination: "Ziel",
  service: "Dienst",
  member: "Mitglied",
  translated: "übersetzt zu",
  zone: "Zone",
  interface: "Interface",
  ref: "verweist auf",
};
const ROLE_OF: Record<string, "src" | "dst" | "svc"> = {
  source_zone: "src",
  source: "src",
  interface: "src",
  destination_zone: "dst",
  destination: "dst",
  translated: "dst",
  service: "svc",
};

const isRule = (n: GNode) => n.type === "rule" || n.type === "nat";
const isBlocking = (n: GNode) => n.type === "rule" && !!n.action && n.action !== "Accept";
const hits = (n: GNode) => n.usage?.hits ?? 0;

function iconFor(n: GNode): LucideIcon {
  if (n.type === "rule") return isBlocking(n) ? ShieldX : ShieldCheck;
  if (n.type === "network" && n.group) return Boxes;
  if (n.type === "network" && n.entity?.startsWith("FQDN")) return Globe;
  if (n.type === "service" && n.group) return Workflow;
  return TYPE_META[n.type].icon;
}

interface Index {
  byId: Map<string, GNode>;
  out: Map<string, GEdge[]>;
  in: Map<string, GEdge[]>;
}

function buildIndex(nodes: GNode[], edges: GEdge[]): Index {
  const idx: Index = { byId: new Map(nodes.map((n) => [n.id, n])), out: new Map(), in: new Map() };
  for (const e of edges) {
    if (!idx.out.has(e.source)) idx.out.set(e.source, []);
    if (!idx.in.has(e.target)) idx.in.set(e.target, []);
    idx.out.get(e.source)!.push(e);
    idx.in.get(e.target)!.push(e);
  }
  return idx;
}

interface RuleRef {
  rule: GNode;
  kind: string;
  via: string | null;
}

/** Alle Regeln, die direkt oder über (verschachtelte) Gruppen auf ein Objekt zeigen. */
function relatedRules(id: string, idx: Index): RuleRef[] {
  const result: RuleRef[] = [];
  const seen = new Set<string>([id]);
  const visit = (target: string, via: string | null) => {
    for (const e of idx.in.get(target) ?? []) {
      const src = idx.byId.get(e.source);
      if (!src) continue;
      if (isRule(src)) result.push({ rule: src, kind: e.kind, via });
      else if (e.kind === "member" && !seen.has(src.id)) {
        seen.add(src.id);
        visit(src.id, via ?? src.name);
      }
    }
  };
  visit(id, null);
  return result;
}

function zonesOf(rule: GNode, idx: Index, kind: "source_zone" | "destination_zone"): string[] {
  const z = (idx.out.get(rule.id) ?? []).filter((e) => e.kind === kind).map((e) => idx.byId.get(e.target)?.name ?? "?");
  return z.length ? z : [ANY_ZONE];
}

// --- Zonen-Matrix -----------------------------------------------------------------

interface Cell {
  rules: GNode[];
  allow: number;
  block: number;
  hits: number;
}

function buildMatrix(nodes: GNode[], idx: Index) {
  const cells = new Map<string, Cell>();
  const src = new Set<string>();
  const dst = new Set<string>();
  for (const r of nodes) {
    if (r.type !== "rule" || r.enabled === false) continue;
    for (const s of zonesOf(r, idx, "source_zone")) {
      for (const d of zonesOf(r, idx, "destination_zone")) {
        src.add(s);
        dst.add(d);
        const key = `${s}>${d}`;
        const c = cells.get(key) ?? { rules: [], allow: 0, block: 0, hits: 0 };
        c.rules.push(r);
        if (isBlocking(r)) c.block++;
        else c.allow++;
        c.hits += hits(r);
        cells.set(key, c);
      }
    }
  }
  const order = (set: Set<string>) => [...set].sort((a, b) => (a === ANY_ZONE ? 1 : b === ANY_ZONE ? -1 : a.localeCompare(b)));
  return { cells, sources: order(src), destinations: order(dst) };
}

function ZoneMatrix({
  matrix,
  selected,
  onSelect,
}: {
  matrix: ReturnType<typeof buildMatrix>;
  selected: string | null;
  onSelect: (key: string) => void;
}) {
  const maxHits = Math.max(1, ...[...matrix.cells.values()].map((c) => c.hits));
  // Sequentielle Ein-Farb-Skala (Treffer, logarithmisch) – die Zahl steht immer in der Zelle
  const intensity = (h: number) => (h <= 0 ? 0 : 0.12 + 0.6 * (Math.log10(h + 1) / Math.log10(maxHits + 1)));
  return (
    <div className="overflow-auto">
      <table className="border-separate border-spacing-1 text-sm">
        <thead>
          <tr>
            <th className="sticky left-0 z-10 bg-card px-2 text-left text-[11px] font-medium text-muted-foreground">Quelle ↓ · Ziel →</th>
            {matrix.destinations.map((d) => (
              <th key={d} className="min-w-28 px-2 pb-1 text-left text-xs font-medium">
                <span className="flex items-center gap-1.5"><Layers className="size-3.5 text-violet-400" />{d}</span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {matrix.sources.map((s) => (
            <tr key={s}>
              <th className="sticky left-0 z-10 bg-card px-2 text-left text-xs font-medium whitespace-nowrap">
                <span className="flex items-center gap-1.5"><Layers className="size-3.5 text-violet-400" />{s}</span>
              </th>
              {matrix.destinations.map((d) => {
                const key = `${s}>${d}`;
                const c = matrix.cells.get(key);
                if (!c) return <td key={d} className="rounded-md border border-dashed border-border/50" />;
                return (
                  <td key={d} className="p-0">
                    <button
                      onClick={() => onSelect(key)}
                      title={`${s} → ${d}: ${c.rules.length} Regeln, ${fmtNumber(c.hits)} Treffer (30 T)`}
                      className={cn(
                        "w-full rounded-md border px-2.5 py-2 text-left transition-all hover:border-primary/60",
                        selected === key && "border-primary ring-2 ring-primary/40",
                      )}
                      style={{ background: `color-mix(in oklch, var(--series-1) ${Math.round(intensity(c.hits) * 100)}%, transparent)` }}
                    >
                      <div className="text-base font-semibold tabular-nums">{c.rules.length}</div>
                      <div className="text-[11px] whitespace-nowrap text-muted-foreground">
                        <span className="text-good">{c.allow}</span> · <span className="text-critical">{c.block}</span> · {fmtNumber(c.hits)}
                      </div>
                    </button>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
      <p className="mt-3 text-xs text-muted-foreground">
        Zahl = aktive Regeln je Zonenpaar · darunter <span className="text-good">erlaubend</span> ·{" "}
        <span className="text-critical">blockierend</span> · Treffer (30 Tage). Farbe = Treffer (logarithmisch). Regeln ohne
        Zonen-Einschränkung erscheinen unter „{ANY_ZONE}“.
      </p>
    </div>
  );
}

// --- Knoten-Darstellung -----------------------------------------------------------

type FlowData = { node?: GNode; any?: string; more?: number; heading?: string; focused?: boolean; selected?: boolean };
type FlowNode = Node<FlowData>;

function EntityNode({ data }: NodeProps<FlowNode>) {
  if (data.heading) {
    return <div className="text-[11px] font-semibold tracking-wider text-muted-foreground uppercase">{data.heading}</div>;
  }
  if (data.any || data.more) {
    return (
      <div className="flex w-[200px] items-center gap-2 rounded-lg border border-dashed bg-card/60 px-3 py-2 text-xs text-muted-foreground">
        <Handle type="target" position={Position.Left} className="!opacity-0" />
        {data.more ? <MoreHorizontal className="size-3.5" /> : <Sparkles className="size-3.5" />}
        {data.any ?? `+${data.more} weitere`}
        <Handle type="source" position={Position.Right} className="!opacity-0" />
      </div>
    );
  }
  const n = data.node!;
  const Icon = iconFor(n);
  const meta = TYPE_META[n.type];
  const tint = n.type === "rule" && isBlocking(n) ? "text-critical bg-critical/12" : meta.tint;
  return (
    <div
      className={cn(
        "w-[200px] rounded-lg border bg-card px-2.5 py-2 shadow-sm",
        data.selected && "border-primary/60 ring-2 ring-primary/40",
        data.focused && "border-primary shadow-glow",
        n.enabled === false && "opacity-55",
      )}
    >
      <Handle type="target" position={Position.Left} className="!size-1.5 !border-0 !bg-muted-foreground/50" />
      <div className="flex items-center gap-2">
        <span className={cn("flex size-7 shrink-0 items-center justify-center rounded-md", tint)}>
          <Icon className="size-4" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="truncate text-xs font-medium" title={n.name}>
            {n.type === "rule" && n.usage?.position != null && <span className="text-muted-foreground">#{n.usage.position + 1} </span>}
            {n.name}
          </div>
          <div className="truncate text-[11px] text-muted-foreground">
            {isRule(n)
              ? `${n.action ?? meta.label}${n.type === "rule" ? ` · ${hits(n) ? `${fmtNumber(hits(n))} Treffer` : "keine Treffer"}` : ""}`
              : n.detail || n.kind || meta.label}
          </div>
        </div>
        {!isRule(n) && n.rule_refs > 0 && (
          <span className="rounded bg-muted px-1.5 text-[10px] tabular-nums text-muted-foreground" title="Direkt verweisende Regeln">
            {n.rule_refs}
          </span>
        )}
      </div>
      <Handle type="source" position={Position.Right} className="!size-1.5 !border-0 !bg-muted-foreground/50" />
    </div>
  );
}

const nodeTypes = { entity: EntityNode };

// --- Fluss-Layout -------------------------------------------------------------------

const COLUMNS = ["Quell-Zonen", "Quellen", "Regeln", "Ziele", "Ziel-Zonen", "Dienste"];
const COL_OF: Record<string, number> = {
  source_zone: 0,
  interface: 0,
  source: 1,
  destination: 3,
  translated: 3,
  ref: 3,
  destination_zone: 4,
  service: 5,
};
const COL_W = 235;
const ROW_H = 64;

function edgeStyle(rule: GNode | undefined, highlighted: boolean) {
  const stroke = highlighted ? "var(--primary)" : rule && isBlocking(rule) ? "var(--critical)" : "var(--muted-foreground)";
  return {
    style: { stroke, strokeWidth: highlighted ? 2 : 1.25, strokeOpacity: highlighted ? 1 : 0.4 },
    markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14, color: stroke },
    animated: highlighted,
  };
}

/** Quell-Zonen → Quellen → Regeln → Ziele → Ziel-Zonen → Dienste; große Spalten werden zusammengefasst. */
function flowLayout(rules: GNode[], idx: Index, focusIds: Set<string>, selected: string | null) {
  const nodes = new Map<string, { col: number; data: FlowData; ruleIdx: number[] }>();
  const rawEdges: { source: string; target: string; rule: GNode; hl: boolean; extra?: Partial<Edge> }[] = [];
  const add = (key: string, col: number, data: FlowData, ruleIndex: number) => {
    const entry = nodes.get(key) ?? { col, data, ruleIdx: [] };
    entry.ruleIdx.push(ruleIndex);
    nodes.set(key, entry);
  };

  rules.forEach((rule, i) => {
    const ruleKey = `2|${rule.id}`;
    add(ruleKey, 2, { node: rule, focused: focusIds.has(rule.id), selected: selected === rule.id }, i);
    const out = idx.out.get(rule.id) ?? [];
    const kinds = new Set(out.map((e) => e.kind));
    for (const e of out) {
      const col = COL_OF[e.kind] ?? 3;
      const target = idx.byId.get(e.target);
      if (!target) continue;
      const key = `${col}|${target.id}`;
      add(key, col, { node: target, focused: focusIds.has(target.id), selected: selected === target.id }, i);
      const hl = selected === target.id || selected === rule.id || focusIds.has(target.id);
      rawEdges.push(col < 2 ? { source: key, target: ruleKey, rule, hl } : { source: ruleKey, target: key, rule, hl });
    }
    if (rule.type === "rule") {
      const anyCols: [string, number, string][] = [
        ["source_zone", 0, "Alle Zonen"],
        ["source", 1, "Alle Quellen"],
        ["destination", 3, "Alle Ziele"],
        ["destination_zone", 4, "Alle Zonen"],
        ["service", 5, "Alle Dienste"],
      ];
      for (const [kind, col, label] of anyCols) {
        if (kinds.has(kind)) continue;
        const key = `${col}|any`;
        add(key, col, { any: label }, i);
        rawEdges.push(col < 2 ? { source: key, target: ruleKey, rule, hl: false } : { source: ruleKey, target: key, rule, hl: false });
      }
    }
  });

  // Fokus-Objekte, die nur über eine Gruppe erreicht werden, neben die Gruppe setzen
  for (const fid of focusIds) {
    const focus = idx.byId.get(fid);
    if (!focus || isRule(focus) || [...nodes.keys()].some((k) => k.endsWith(`|${fid}`))) continue;
    for (const e of idx.in.get(fid) ?? []) {
      if (e.kind !== "member") continue;
      for (const [key, entry] of [...nodes]) {
        if (!key.endsWith(`|${e.source}`)) continue;
        const fkey = `${entry.col}|${fid}`;
        nodes.set(fkey, { col: entry.col, data: { node: focus, focused: true, selected: selected === fid }, ruleIdx: entry.ruleIdx });
        rawEdges.push({
          source: entry.col < 2 ? fkey : key,
          target: entry.col < 2 ? key : fkey,
          rule: focus,
          hl: true,
          extra: { label: "Mitglied", style: { stroke: "var(--primary)", strokeDasharray: "4 3", strokeWidth: 1.5 } },
        });
      }
    }
  }

  // Große Spalten: die meistverbundenen Objekte zeigen, den Rest zu "+N weitere" zusammenfassen
  const replace = new Map<string, string>();
  const columns: string[][] = COLUMNS.map(() => []);
  for (const [key, entry] of nodes) columns[entry.col].push(key);
  columns.forEach((keys, col) => {
    if (col === 2 || keys.length <= COLUMN_LIMIT) return;
    const weight = (k: string) => (nodes.get(k)!.data.focused ? 1e9 : 0) + nodes.get(k)!.ruleIdx.length;
    const keep = [...keys].sort((a, b) => weight(b) - weight(a)).slice(0, COLUMN_LIMIT - 1);
    const keepSet = new Set(keep);
    const moreKey = `${col}|more`;
    const dropped = keys.filter((k) => !keepSet.has(k));
    const ruleIdx = dropped.flatMap((k) => nodes.get(k)!.ruleIdx);
    for (const k of dropped) {
      replace.set(k, moreKey);
      nodes.delete(k);
    }
    nodes.set(moreKey, { col, data: { more: dropped.length }, ruleIdx });
    columns[col] = [...keep, moreKey];
  });

  const edges: Edge[] = [];
  const seen = new Set<string>();
  for (const e of rawEdges) {
    const source = replace.get(e.source) ?? e.source;
    const target = replace.get(e.target) ?? e.target;
    const id = `${source}>${target}`;
    if (seen.has(id)) continue;
    seen.add(id);
    edges.push({ id, source, target, ...edgeStyle(e.rule, e.hl), ...e.extra });
  }

  // Spalten nach Schwerpunkt der verbundenen Regeln sortieren – weniger Kreuzungen
  const center = (k: string) => {
    if (k.endsWith("|more")) return Infinity;
    const r = nodes.get(k)!.ruleIdx;
    return r.reduce((a, b) => a + b, 0) / Math.max(1, r.length);
  };
  const maxRows = Math.max(...columns.map((c) => c.length), 1);
  const flowNodes: FlowNode[] = [];
  columns.forEach((keys, col) => {
    if (col !== 2) keys.sort((a, b) => center(a) - center(b));
    const offset = ((maxRows - keys.length) * ROW_H) / 2;
    if (keys.length) {
      flowNodes.push({
        id: `heading-${col}`,
        type: "entity",
        position: { x: col * COL_W, y: -44 },
        data: { heading: COLUMNS[col] },
        selectable: false,
        draggable: false,
      });
    }
    keys.forEach((key, row) => {
      flowNodes.push({ id: key, type: "entity", position: { x: col * COL_W, y: offset + row * ROW_H }, data: nodes.get(key)!.data });
    });
  });
  return { nodes: flowNodes, edges };
}

// --- Seitenteile -----------------------------------------------------------------

function ObjectSearch({ nodes, onPick }: { nodes: GNode[]; onPick: (id: string) => void }) {
  const [open, setOpen] = useState(false);
  const groups = (Object.keys(TYPE_META) as NodeType[])
    .map((t) => [t, nodes.filter((n) => n.type === t).sort((a, b) => a.name.localeCompare(b.name))] as const)
    .filter(([, list]) => list.length);
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button variant="outline" className="w-72 justify-start gap-2 text-muted-foreground">
          <Search className="size-4" /> Objekt, Regel, Zone suchen …
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-80 p-0" align="start">
        <Command>
          <CommandInput placeholder="Name eingeben …" />
          <CommandList className="max-h-96">
            <CommandEmpty>Nichts gefunden.</CommandEmpty>
            {groups.map(([t, list]) => (
              <CommandGroup key={t} heading={TYPE_META[t].plural}>
                {list.map((n) => {
                  const Icon = iconFor(n);
                  return (
                    <CommandItem key={n.id} value={`${n.name} ${n.detail ?? ""} ${t}`} onSelect={() => { onPick(n.id); setOpen(false); }}>
                      <Icon />
                      <span className="truncate">{n.name}</span>
                      {n.detail && <span className="ml-auto truncate text-xs text-muted-foreground">{n.detail}</span>}
                    </CommandItem>
                  );
                })}
              </CommandGroup>
            ))}
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}

function NodeLink({ n, onPick, extra }: { n: GNode; onPick: (id: string) => void; extra?: string }) {
  const Icon = iconFor(n);
  return (
    <button onClick={() => onPick(n.id)} className="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm hover:bg-accent">
      <Icon className={cn("size-4 shrink-0", isBlocking(n) ? "text-critical" : "text-muted-foreground")} />
      <span className="min-w-0 flex-1 truncate">
        {n.type === "rule" && n.usage?.position != null && <span className="text-muted-foreground">#{n.usage.position + 1} </span>}
        {n.name}
      </span>
      {extra && <span className="shrink-0 text-xs text-muted-foreground">{extra}</span>}
    </button>
  );
}

/** Lange Listen erst gekürzt zeigen – bei Zonen mit hunderten Regeln bleibt das Panel bedienbar. */
function LimitedList<T>({ items, render, limit = 50 }: { items: T[]; render: (item: T, i: number) => ReactNode; limit?: number }) {
  const [all, setAll] = useState(false);
  const shown = all ? items : items.slice(0, limit);
  return (
    <>
      {shown.map(render)}
      {items.length > limit && (
        <Button variant="ghost" size="sm" className="w-full text-xs" onClick={() => setAll(!all)}>
          {all ? "Weniger anzeigen" : `Alle ${items.length} anzeigen`}
        </Button>
      )}
    </>
  );
}

function DetailPanel({ node, idx, onPick, onFocus, onClose }: {
  node: GNode;
  idx: Index;
  onPick: (id: string) => void;
  onFocus: (id: string) => void;
  onClose: () => void;
}) {
  const meta = TYPE_META[node.type];
  const Icon = iconFor(node);
  const refs = useMemo(
    () => (isRule(node) ? [] : relatedRules(node.id, idx).sort((a, b) => hits(b.rule) - hits(a.rule))),
    [node, idx],
  );
  const out = idx.out.get(node.id) ?? [];
  const members = out.filter((e) => e.kind === "member").map((e) => idx.byId.get(e.target)!).filter(Boolean);
  const memberOf = (idx.in.get(node.id) ?? []).filter((e) => e.kind === "member").map((e) => idx.byId.get(e.source)!).filter(Boolean);
  const zoneIfaces =
    node.type === "zone" ? (idx.in.get(node.id) ?? []).map((e) => idx.byId.get(e.source)!).filter((n) => n && n.type === "interface") : [];
  const ruleTargets = isRule(node) ? out.map((e) => ({ e, n: idx.byId.get(e.target)! })).filter((x) => x.n) : [];
  const allow = refs.filter((r) => r.rule.type === "rule" && !isBlocking(r.rule)).length;
  const block = refs.filter((r) => isBlocking(r.rule)).length;

  return (
    <Card className="flex h-full min-h-0 flex-col gap-0 py-0">
      <CardHeader className="border-b px-4 py-3">
        <div className="flex items-start gap-3">
          <span className={cn("flex size-9 shrink-0 items-center justify-center rounded-lg", isBlocking(node) ? "bg-critical/12 text-critical" : meta.tint)}>
            <Icon className="size-5" />
          </span>
          <div className="min-w-0 flex-1">
            <CardTitle className="truncate text-sm" title={node.name}>{node.name}</CardTitle>
            <div className="text-xs text-muted-foreground">
              {meta.label}
              {node.group && " · Gruppe"}
              {node.builtin && " · eingebaut/nicht abgerufen"}
            </div>
          </div>
          <Button variant="ghost" size="icon" className="size-7" onClick={onClose} aria-label="Schließen"><X /></Button>
        </div>
        <Button size="sm" variant="secondary" className="mt-2 w-full" onClick={() => onFocus(node.id)}>
          <Crosshair /> Im Graph anzeigen
        </Button>
      </CardHeader>
      <ScrollArea className="min-h-0 flex-1">
        <CardContent className="space-y-5 px-4 py-4 text-sm">
          {node.detail && (
            <div>
              <div className="label">Details</div>
              <div className="font-mono text-xs">{node.detail}</div>
            </div>
          )}
          {isRule(node) && (
            <div className="grid grid-cols-2 gap-2">
              <div className="rounded-md bg-muted/50 p-2">
                <div className="text-[11px] text-muted-foreground">Aktion</div>
                <Pill tone={isBlocking(node) ? "critical" : "good"}>{node.action ?? "–"}</Pill>
              </div>
              <div className="rounded-md bg-muted/50 p-2">
                <div className="text-[11px] text-muted-foreground">Status</div>
                <div className="text-xs font-medium">{node.enabled === false ? "deaktiviert" : "aktiv"}</div>
              </div>
              {node.type === "rule" && (
                <>
                  <div className="rounded-md bg-muted/50 p-2">
                    <div className="text-[11px] text-muted-foreground">Treffer (30 T)</div>
                    <div className="text-xs font-medium tabular-nums">{fmtNumber(hits(node))}</div>
                  </div>
                  <div className="rounded-md bg-muted/50 p-2">
                    <div className="text-[11px] text-muted-foreground">Volumen (30 T)</div>
                    <div className="text-xs font-medium tabular-nums">{fmtBytes((node.usage?.sent_bytes ?? 0) + (node.usage?.recv_bytes ?? 0))}</div>
                  </div>
                  <div className="col-span-2 rounded-md bg-muted/50 p-2">
                    <div className="text-[11px] text-muted-foreground">Zuletzt genutzt</div>
                    <div className="text-xs font-medium">{fmtRelative(node.usage?.last_seen_ever)}</div>
                  </div>
                </>
              )}
            </div>
          )}
          {ruleTargets.length > 0 && (
            <div className="space-y-1">
              <div className="label">Verweist auf</div>
              {ruleTargets.map(({ e, n }) => <NodeLink key={`${e.kind}-${n.id}`} n={n} onPick={onPick} extra={EDGE_LABEL[e.kind] ?? e.kind} />)}
            </div>
          )}
          {!isRule(node) && (
            <div className="space-y-1">
              <div className="label flex items-center justify-between">
                <span>Verwendet in {refs.length} Regel(n)</span>
                {refs.length > 0 && (
                  <span className="font-normal">
                    <span className="text-good">{allow} erl.</span> · <span className="text-critical">{block} blk.</span>
                  </span>
                )}
              </div>
              {refs.length === 0 && <div className="text-xs text-muted-foreground">Keine Regel verweist auf dieses Objekt.</div>}
              <LimitedList
                items={refs}
                render={(r, i) => (
                  <NodeLink key={`${r.rule.id}-${r.kind}-${i}`} n={r.rule} onPick={onPick} extra={`${EDGE_LABEL[r.kind] ?? r.kind}${r.via ? ` · via ${r.via}` : ""}`} />
                )}
              />
            </div>
          )}
          {members.length > 0 && (
            <div className="space-y-1">
              <div className="label">Mitglieder ({members.length})</div>
              <LimitedList items={members} render={(m) => <NodeLink key={m.id} n={m} onPick={onPick} extra={m.detail} />} />
            </div>
          )}
          {memberOf.length > 0 && (
            <div className="space-y-1">
              <div className="label">Mitglied von</div>
              {memberOf.map((m) => <NodeLink key={m.id} n={m} onPick={onPick} />)}
            </div>
          )}
          {zoneIfaces.length > 0 && (
            <div className="space-y-1">
              <div className="label">Interfaces in dieser Zone</div>
              {zoneIfaces.map((m) => <NodeLink key={m.id} n={m} onPick={onPick} extra={m.detail} />)}
            </div>
          )}
          {node.data != null && (
            <details>
              <summary className="cursor-pointer text-xs text-muted-foreground hover:text-foreground">Rohdaten (XML-API)</summary>
              <pre className="mt-2 max-h-72 overflow-auto rounded-md bg-muted/50 p-2 text-[11px]">{JSON.stringify(node.data, null, 2)}</pre>
            </details>
          )}
        </CardContent>
      </ScrollArea>
    </Card>
  );
}

/** Regelliste einer Matrix-Zelle (Zonenpaar), sortiert nach Nutzung. */
function CellPanel({ title, cell, onPick, onShowGraph, onClose }: {
  title: string;
  cell: Cell;
  onPick: (id: string) => void;
  onShowGraph: () => void;
  onClose: () => void;
}) {
  const [filter, setFilter] = useState("");
  const rules = [...cell.rules].filter((r) => r.name.toLowerCase().includes(filter.toLowerCase())).sort((a, b) => hits(b) - hits(a));
  return (
    <Card className="flex h-full min-h-0 flex-col gap-0 py-0">
      <CardHeader className="border-b px-4 py-3">
        <div className="flex items-start gap-3">
          <span className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-violet-500/12 text-violet-400"><Grid3x3 className="size-5" /></span>
          <div className="min-w-0 flex-1">
            <CardTitle className="truncate text-sm">{title}</CardTitle>
            <div className="text-xs text-muted-foreground">
              {cell.rules.length} Regeln · <span className="text-good">{cell.allow} erl.</span> · <span className="text-critical">{cell.block} blk.</span> ·{" "}
              {fmtNumber(cell.hits)} Treffer
            </div>
          </div>
          <Button variant="ghost" size="icon" className="size-7" onClick={onClose} aria-label="Schließen"><X /></Button>
        </div>
        <Button size="sm" className="mt-2 w-full" onClick={onShowGraph}>
          <Crosshair /> Als Graph anzeigen{cell.rules.length > LIMITS[0] && ` (Top ${LIMITS[0]})`}
        </Button>
        <Input className="mt-2 h-8" placeholder="Regeln filtern …" value={filter} onChange={(e) => setFilter(e.target.value)} />
      </CardHeader>
      <ScrollArea className="min-h-0 flex-1">
        <div className="p-2">
          <LimitedList items={rules} limit={100} render={(r) => <NodeLink key={r.id} n={r} onPick={onPick} extra={hits(r) ? fmtNumber(hits(r)) : "–"} />} />
        </div>
      </ScrollArea>
    </Card>
  );
}

// --- Hauptkomponente -----------------------------------------------------------------

type Role = "all" | "src" | "dst" | "svc";
type ActionFilter = "all" | "allow" | "block";

export function GraphTab({ fwId }: { fwId: number }) {
  const { theme } = useTheme();
  const q = useQuery({
    queryKey: ["graph", fwId],
    queryFn: () => api<{ nodes: GNode[]; edges: GEdge[] }>(`/api/firewalls/${fwId}/graph`),
  });

  // Ansicht und Fokus stehen in der URL – verlinkbar und teilbar
  const [params, setParams] = useSearchParams();
  const focusId = params.get("focus");
  const cellKey = params.get("cell");
  const view = focusId ? "focus" : "matrix";
  const setUrl = (changes: Record<string, string | null>) =>
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        for (const [k, v] of Object.entries(changes)) {
          if (v) next.set(k, v);
          else next.delete(k);
        }
        return next;
      },
      { replace: true },
    );

  const [selected, setSelected] = useState<string | null>(focusId && !focusId.startsWith("cell:") ? focusId : null);
  const [role, setRole] = useState<Role>("all");
  const [actionFilter, setActionFilter] = useState<ActionFilter>("all");
  const [text, setText] = useState("");
  const [limit, setLimit] = useState(LIMITS[0]);

  const idx = useMemo(() => buildIndex(q.data?.nodes ?? [], q.data?.edges ?? []), [q.data]);
  const matrix = useMemo(() => buildMatrix(q.data?.nodes ?? [], idx), [q.data, idx]);

  // Fokus = ein Objekt (focus=network:X) oder ein Zonenpaar aus der Matrix (focus=cell:LAN>WAN)
  const focusNode = focusId && !focusId.startsWith("cell:") ? idx.byId.get(focusId) ?? null : null;
  const focusCell = focusId?.startsWith("cell:") ? matrix.cells.get(focusId.slice(5)) ?? null : null;

  const candidates = useMemo((): RuleRef[] => {
    if (focusCell) return focusCell.rules.map((rule) => ({ rule, kind: "", via: null }));
    if (!focusNode) return [];
    if (isRule(focusNode)) return [{ rule: focusNode, kind: "", via: null }];
    return relatedRules(focusNode.id, idx);
  }, [focusNode, focusCell, idx]);

  const filtered = useMemo(() => {
    const t = text.toLowerCase();
    const byId = new Map<string, GNode>();
    for (const c of candidates) {
      if (role !== "all" && ROLE_OF[c.kind] !== role) continue;
      if (actionFilter === "allow" && isBlocking(c.rule)) continue;
      if (actionFilter === "block" && !isBlocking(c.rule)) continue;
      if (t && !c.rule.name.toLowerCase().includes(t)) continue;
      byId.set(c.rule.id, c.rule);
    }
    return [...byId.values()].sort((a, b) => hits(b) - hits(a));
  }, [candidates, role, actionFilter, text]);
  const totalRules = useMemo(() => new Set(candidates.map((c) => c.rule.id)).size, [candidates]);

  const flow = useMemo(() => {
    if (view !== "focus") return { nodes: [], edges: [] };
    const shown = filtered.slice(0, limit).sort((a, b) => (a.usage?.position ?? 1e9) - (b.usage?.position ?? 1e9));
    return flowLayout(shown, idx, new Set(focusNode ? [focusNode.id] : []), selected);
  }, [view, filtered, idx, focusNode, selected, limit]);

  if (q.isPending) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  if (q.data.nodes.length === 0) return <Empty>Noch keine Konfiguration abgerufen (XML-API prüfen)</Empty>;

  const doFocus = (id: string) => {
    setUrl({ focus: id, cell: null });
    setSelected(id.startsWith("cell:") ? null : id);
    setRole("all");
    setActionFilter("all");
    setText("");
  };
  const selectedNode = selected ? idx.byId.get(selected) : undefined;
  const cell = cellKey ? matrix.cells.get(cellKey) : undefined;
  const focusLabel = focusNode?.name ?? (focusCell ? focusId!.slice(5).replace(">", " → ") : null);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <ObjectSearch nodes={q.data.nodes} onPick={doFocus} />
        <ToggleGroup type="single" variant="outline" size="sm" value={view} onValueChange={(v) => v === "matrix" && setUrl({ focus: null })}>
          <ToggleGroupItem value="matrix" className="px-3"><Grid3x3 className="size-4" />Zonen-Matrix</ToggleGroupItem>
          <ToggleGroupItem value="focus" className="px-3" disabled={!focusId}><Crosshair className="size-4" />Fokus</ToggleGroupItem>
        </ToggleGroup>
        {focusLabel && (
          <Badge variant="outline" className="gap-1.5 border-primary/40 py-1">
            <Crosshair className="size-3 text-primary" /> {focusLabel}
            <button onClick={() => setUrl({ focus: null })} aria-label="Fokus entfernen"><X className="size-3" /></button>
          </Badge>
        )}
        <span className="ml-auto text-xs text-muted-foreground">
          {q.data.nodes.length} Objekte · {q.data.edges.length} Beziehungen
        </span>
      </div>

      {view === "focus" && totalRules > 1 && (
        <div className="flex flex-wrap items-center gap-2 rounded-xl border bg-card/60 px-3 py-2">
          {!focusCell && (
            <ToggleGroup type="single" variant="outline" size="sm" value={role} onValueChange={(v) => v && setRole(v as Role)}>
              <ToggleGroupItem value="all" className="px-2.5 text-xs">Alle Rollen</ToggleGroupItem>
              <ToggleGroupItem value="src" className="px-2.5 text-xs">als Quelle</ToggleGroupItem>
              <ToggleGroupItem value="dst" className="px-2.5 text-xs">als Ziel</ToggleGroupItem>
              <ToggleGroupItem value="svc" className="px-2.5 text-xs">als Dienst</ToggleGroupItem>
            </ToggleGroup>
          )}
          <ToggleGroup type="single" variant="outline" size="sm" value={actionFilter} onValueChange={(v) => v && setActionFilter(v as ActionFilter)}>
            <ToggleGroupItem value="all" className="px-2.5 text-xs">Alle Aktionen</ToggleGroupItem>
            <ToggleGroupItem value="allow" className="px-2.5 text-xs">erlaubend</ToggleGroupItem>
            <ToggleGroupItem value="block" className="px-2.5 text-xs">blockierend</ToggleGroupItem>
          </ToggleGroup>
          <Input className="h-8 w-56" placeholder="Regelname filtern …" value={text} onChange={(e) => setText(e.target.value)} />
          <span className="ml-auto text-xs text-muted-foreground">
            {filtered.length > limit
              ? `${filtered.length} von ${totalRules} Regeln – angezeigt: Top ${limit} nach Treffern`
              : `${filtered.length} von ${totalRules} Regeln`}
          </span>
          {filtered.length > LIMITS[0] && (
            <ToggleGroup type="single" variant="outline" size="sm" value={String(limit)} onValueChange={(v) => v && setLimit(Number(v))} aria-label="Anzahl Regeln im Graph">
              {LIMITS.map((l) => <ToggleGroupItem key={l} value={String(l)} className="px-2.5 text-xs">{l}</ToggleGroupItem>)}
            </ToggleGroup>
          )}
        </div>
      )}

      <div className="grid h-[calc(100vh-19rem)] min-h-[520px] gap-3 lg:grid-cols-[1fr_22rem]">
        <div className="relative min-w-0 overflow-hidden rounded-xl border bg-card/40">
          {view === "matrix" ? (
            <ScrollArea className="h-full">
              <div className="p-4">
                {matrix.sources.length === 0 ? (
                  <Empty>Keine aktiven Firewall-Regeln gefunden.</Empty>
                ) : (
                  <ZoneMatrix matrix={matrix} selected={cellKey} onSelect={(k) => { setUrl({ cell: k }); setSelected(null); }} />
                )}
              </div>
            </ScrollArea>
          ) : flow.nodes.length === 0 ? (
            <Empty>{totalRules ? "Keine Regel passt zu den Filtern." : "Keine Regel verweist auf dieses Objekt."}</Empty>
          ) : (
            <ReactFlow
              key={`${focusId}-${role}-${actionFilter}-${text}-${limit}`}
              nodes={flow.nodes}
              edges={flow.edges}
              nodeTypes={nodeTypes}
              colorMode={theme}
              fitView
              fitViewOptions={{ padding: 0.06, maxZoom: 1.2 }}
              minZoom={0.1}
              onlyRenderVisibleElements
              nodesConnectable={false}
              onNodeClick={(_, n) => n.data.node && setSelected(n.data.node.id)}
              onNodeDoubleClick={(_, n) => n.data.node && doFocus(n.data.node.id)}
              onPaneClick={() => setSelected(null)}
              proOptions={{ hideAttribution: true }}
              style={{ "--xy-background-color": "transparent" } as CSSProperties}
            >
              <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="var(--grid)" />
              <Controls showInteractive={false} />
            </ReactFlow>
          )}
          {view === "focus" && (
            <div className="pointer-events-none absolute bottom-3 left-14 text-[11px] text-muted-foreground">Klick: Details · Doppelklick: Fokus</div>
          )}
        </div>

        {selectedNode ? (
          <DetailPanel node={selectedNode} idx={idx} onPick={setSelected} onFocus={doFocus} onClose={() => setSelected(null)} />
        ) : (view === "matrix" && cell) || focusCell ? (
          <CellPanel
            title={(cellKey ?? focusId!.slice(5)).replace(">", " → ")}
            cell={(cell ?? focusCell)!}
            onPick={setSelected}
            onShowGraph={() => doFocus(`cell:${cellKey ?? focusId!.slice(5)}`)}
            onClose={() => setUrl({ cell: null, focus: null })}
          />
        ) : (
          <Card className="hidden gap-3 lg:flex">
            <CardContent className="space-y-3 text-sm text-muted-foreground">
              <div className="font-medium text-foreground">{view === "matrix" ? "Zonen-Matrix" : "Legende"}</div>
              {view === "matrix" ? (
                <p>
                  Eine Zelle anklicken, um die Regeln zwischen zwei Zonen zu sehen – sortiert nach Nutzung. Von dort lässt sich das
                  Zonenpaar oder eine einzelne Regel als Graph anzeigen. Oder oben nach einem Objekt suchen.
                </p>
              ) : (
                <>
                  {(Object.keys(TYPE_META) as NodeType[]).map((t) => {
                    const Icon = TYPE_META[t].icon;
                    return (
                      <div key={t} className="flex items-center gap-2">
                        <span className={cn("flex size-6 items-center justify-center rounded-md", TYPE_META[t].tint)}><Icon className="size-3.5" /></span>
                        {TYPE_META[t].plural}
                      </div>
                    );
                  })}
                  <div className="flex items-center gap-2">
                    <span className="flex size-6 items-center justify-center rounded-md bg-critical/12 text-critical"><ShieldX className="size-3.5" /></span>
                    Blockierende Regel
                  </div>
                  <p className="pt-2 text-xs">
                    Zahl am Objekt = direkt verweisende Regeln. „Alle …“ = keine Einschränkung (Any). Große Spalten werden zu „+N weitere“
                    zusammengefasst.
                  </p>
                </>
              )}
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
