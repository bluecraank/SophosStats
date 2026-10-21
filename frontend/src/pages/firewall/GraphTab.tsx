import { graphlib, layout } from "@dagrejs/dagre";
import { useQuery } from "@tanstack/react-query";
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
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
  Layers,
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
import { useMemo, useState, type CSSProperties } from "react";
import { useSearchParams } from "react-router";
import { Empty, ErrorBox, Loading, Pill } from "@/components/ui";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
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

const isRule = (n: GNode) => n.type === "rule" || n.type === "nat";
const isBlocking = (n: GNode) => n.type === "rule" && !!n.action && n.action !== "Accept";

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
  return result.sort((a, b) => (a.rule.usage?.position ?? 1e9) - (b.rule.usage?.position ?? 1e9));
}

// --- Knoten-Darstellung -----------------------------------------------------------

type FlowData = { node?: GNode; any?: string; heading?: string; focused?: boolean; selected?: boolean };
type FlowNode = Node<FlowData>;

function EntityNode({ data }: NodeProps<FlowNode>) {
  if (data.heading) {
    return <div className="text-[11px] font-semibold tracking-wider text-muted-foreground uppercase">{data.heading}</div>;
  }
  if (data.any) {
    return (
      <div className="flex w-[210px] items-center gap-2 rounded-lg border border-dashed bg-card/60 px-3 py-2 text-xs text-muted-foreground">
        <Handle type="target" position={Position.Left} className="!opacity-0" />
        <Sparkles className="size-3.5" /> {data.any}
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
        "w-[210px] rounded-lg border bg-card px-2.5 py-2 shadow-sm transition-shadow",
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
              ? `${n.action ?? meta.label}${n.usage?.hits ? ` · ${fmtNumber(n.usage.hits)} Treffer` : n.type === "rule" ? " · keine Treffer" : ""}`
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

// --- Layouts ------------------------------------------------------------------------

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
const COL_W = 245;
const ROW_H = 68;

function edgeStyle(rule: GNode | undefined, highlighted: boolean) {
  const stroke = highlighted ? "var(--primary)" : rule && isBlocking(rule) ? "var(--critical)" : "var(--muted-foreground)";
  return {
    style: { stroke, strokeWidth: highlighted ? 2 : 1.25, strokeOpacity: highlighted ? 1 : 0.45 },
    markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14, color: stroke },
    animated: highlighted,
  };
}

/** Fluss-Layout: Quell-Zonen → Quellen → Regeln → Ziele → Ziel-Zonen → Dienste. */
function flowLayout(rules: GNode[], idx: Index, focus: GNode | null, selected: string | null) {
  const nodes = new Map<string, { col: number; data: FlowData; ruleIdx: number[] }>();
  const edges: Edge[] = [];
  const add = (key: string, col: number, data: FlowData, ruleIndex: number) => {
    const entry = nodes.get(key) ?? { col, data, ruleIdx: [] };
    entry.ruleIdx.push(ruleIndex);
    nodes.set(key, entry);
  };

  rules.forEach((rule, i) => {
    const ruleKey = `2|${rule.id}`;
    add(ruleKey, 2, { node: rule, focused: focus?.id === rule.id, selected: selected === rule.id }, i);
    const out = idx.out.get(rule.id) ?? [];
    const kinds = new Set(out.map((e) => e.kind));
    for (const e of out) {
      const col = COL_OF[e.kind] ?? 3;
      const target = idx.byId.get(e.target);
      if (!target) continue;
      const key = `${col}|${target.id}`;
      add(key, col, { node: target, focused: focus?.id === target.id, selected: selected === target.id }, i);
      const hl = selected === target.id || selected === rule.id || focus?.id === target.id;
      edges.push({
        id: `${ruleKey}>${key}>${e.kind}`,
        source: col < 2 ? key : ruleKey,
        target: col < 2 ? ruleKey : key,
        ...edgeStyle(rule, hl),
      });
    }
    // Fehlende Einschränkung = "Alle" sichtbar machen
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
        edges.push({ id: `${ruleKey}>${key}`, source: col < 2 ? key : ruleKey, target: col < 2 ? ruleKey : key, ...edgeStyle(rule, false) });
      }
    }
  });

  // Fokus-Objekt, das nur über eine Gruppe erreicht wird, neben die Gruppe setzen
  if (focus && !isRule(focus) && ![...nodes.keys()].some((k) => k.endsWith(`|${focus.id}`))) {
    for (const e of idx.in.get(focus.id) ?? []) {
      if (e.kind !== "member") continue;
      for (const [key, entry] of nodes) {
        if (!key.endsWith(`|${e.source}`)) continue;
        const fkey = `${entry.col}|${focus.id}`;
        nodes.set(fkey, { col: entry.col, data: { node: focus, focused: true, selected: selected === focus.id }, ruleIdx: entry.ruleIdx });
        edges.push({
          id: `${fkey}~${key}`,
          source: entry.col < 2 ? fkey : key,
          target: entry.col < 2 ? key : fkey,
          label: "Mitglied",
          labelStyle: { fill: "var(--muted-foreground)", fontSize: 10 },
          labelBgStyle: { fill: "var(--card)" },
          style: { stroke: "var(--primary)", strokeDasharray: "4 3", strokeWidth: 1.5 },
        });
      }
    }
  }

  // Spalten nach Schwerpunkt der verbundenen Regeln sortieren – weniger Kreuzungen
  const columns: string[][] = COLUMNS.map(() => []);
  for (const [key, entry] of nodes) columns[entry.col].push(key);
  const center = (k: string) => {
    const r = nodes.get(k)!.ruleIdx;
    return r.reduce((a, b) => a + b, 0) / r.length;
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

/** Gesamtansicht: automatisches Layout (dagre, links → rechts) für die gefilterten Typen. */
function overviewLayout(all: GNode[], allEdges: GEdge[], types: Set<NodeType>, selected: string | null, idx: Index) {
  const shown = all.filter((n) => types.has(n.type));
  const ids = new Set(shown.map((n) => n.id));
  const edges = allEdges.filter((e) => ids.has(e.source) && ids.has(e.target));
  const connected = new Set(edges.flatMap((e) => [e.source, e.target]));
  const nodes = shown.filter((n) => connected.has(n.id));

  const g = new graphlib.Graph();
  g.setGraph({ rankdir: "LR", nodesep: 14, ranksep: 90, marginx: 20, marginy: 20 });
  g.setDefaultEdgeLabel(() => ({}));
  nodes.forEach((n) => g.setNode(n.id, { width: 210, height: 52 }));
  edges.forEach((e) => g.setEdge(e.source, e.target));
  layout(g);

  return {
    nodes: nodes.map((n): FlowNode => {
      const p = g.node(n.id);
      return { id: n.id, type: "entity", position: { x: p.x - 105, y: p.y - 26 }, data: { node: n, selected: selected === n.id } };
    }),
    edges: edges.map(
      (e): Edge => ({
        id: `${e.source}>${e.target}>${e.kind}`,
        source: e.source,
        target: e.target,
        ...edgeStyle(idx.byId.get(e.source), selected === e.source || selected === e.target),
      }),
    ),
  };
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
    <button
      onClick={() => onPick(n.id)}
      className="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm hover:bg-accent"
    >
      <Icon className={cn("size-4 shrink-0", isBlocking(n) ? "text-critical" : "text-muted-foreground")} />
      <span className="min-w-0 flex-1 truncate">
        {n.type === "rule" && n.usage?.position != null && <span className="text-muted-foreground">#{n.usage.position + 1} </span>}
        {n.name}
      </span>
      {extra && <span className="shrink-0 text-xs text-muted-foreground">{extra}</span>}
    </button>
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
  const refs = isRule(node) ? [] : relatedRules(node.id, idx);
  const out = idx.out.get(node.id) ?? [];
  const members = out.filter((e) => e.kind === "member").map((e) => idx.byId.get(e.target)!).filter(Boolean);
  const memberOf = (idx.in.get(node.id) ?? []).filter((e) => e.kind === "member").map((e) => idx.byId.get(e.source)!).filter(Boolean);
  const zoneIfaces = node.type === "zone" ? (idx.in.get(node.id) ?? []).map((e) => idx.byId.get(e.source)!).filter((n) => n && n.type === "interface") : [];
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
          <Button variant="ghost" size="icon" className="size-7" onClick={onClose} aria-label="Schließen">
            <X />
          </Button>
        </div>
        <Button size="sm" variant="secondary" className="mt-2 w-full" onClick={() => onFocus(node.id)}>
          <Crosshair /> Fokus auf dieses Objekt
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
                    <div className="text-xs font-medium tabular-nums">{fmtNumber(node.usage?.hits ?? 0)}</div>
                  </div>
                  <div className="rounded-md bg-muted/50 p-2">
                    <div className="text-[11px] text-muted-foreground">Volumen (30 T)</div>
                    <div className="text-xs font-medium tabular-nums">
                      {fmtBytes((node.usage?.sent_bytes ?? 0) + (node.usage?.recv_bytes ?? 0))}
                    </div>
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
              {ruleTargets.map(({ e, n }) => (
                <NodeLink key={`${e.kind}-${n.id}`} n={n} onPick={onPick} extra={EDGE_LABEL[e.kind] ?? e.kind} />
              ))}
            </div>
          )}

          {!isRule(node) && (
            <div className="space-y-1">
              <div className="label flex items-center justify-between">
                <span>Verwendet in {refs.length} Regel(n)</span>
                {refs.length > 0 && (
                  <span className="font-normal">
                    <span className="text-good">{allow} erlaubend</span> · <span className="text-critical">{block} blockierend</span>
                  </span>
                )}
              </div>
              {refs.length === 0 && <div className="text-xs text-muted-foreground">Keine Regel verweist auf dieses Objekt.</div>}
              {refs.map((r, i) => (
                <NodeLink
                  key={`${r.rule.id}-${r.kind}-${i}`}
                  n={r.rule}
                  onPick={onPick}
                  extra={`${EDGE_LABEL[r.kind] ?? r.kind}${r.via ? ` · via ${r.via}` : ""}`}
                />
              ))}
            </div>
          )}

          {members.length > 0 && (
            <div className="space-y-1">
              <div className="label">Mitglieder ({members.length})</div>
              {members.map((m) => <NodeLink key={m.id} n={m} onPick={onPick} extra={m.detail} />)}
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

// --- Hauptkomponente -----------------------------------------------------------------

const ALL_TYPES: NodeType[] = ["zone", "interface", "network", "service", "rule", "nat"];

export function GraphTab({ fwId }: { fwId: number }) {
  const { theme } = useTheme();
  const q = useQuery({
    queryKey: ["graph", fwId],
    queryFn: () => api<{ nodes: GNode[]; edges: GEdge[] }>(`/api/firewalls/${fwId}/graph`),
  });
  const [mode, setMode] = useState<"focus" | "overview">("focus");
  // Fokus steht in der URL (?focus=network:Webserver) – verlinkbar und teilbar
  const [params, setParams] = useSearchParams();
  const focusId = params.get("focus");
  const setFocusId = (id: string | null) =>
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (id) next.set("focus", id);
        else next.delete("focus");
        return next;
      },
      { replace: true },
    );
  const [selected, setSelected] = useState<string | null>(focusId);
  const [types, setTypes] = useState<Set<NodeType>>(new Set(["zone", "network", "service", "rule"]));

  const idx = useMemo(() => buildIndex(q.data?.nodes ?? [], q.data?.edges ?? []), [q.data]);
  const focus = focusId ? idx.byId.get(focusId) ?? null : null;

  const flow = useMemo(() => {
    if (!q.data) return { nodes: [], edges: [] };
    if (mode === "overview") return overviewLayout(q.data.nodes, q.data.edges, types, selected, idx);
    if (!focus) return { nodes: [], edges: [] };
    const rules = isRule(focus)
      ? [focus]
      : [...new Map(relatedRules(focus.id, idx).map((r) => [r.rule.id, r.rule])).values()];
    return flowLayout(rules, idx, focus, selected);
  }, [q.data, mode, types, selected, focus, idx]);

  if (q.isPending) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  if (q.data.nodes.length === 0) return <Empty>Noch keine Konfiguration abgerufen (XML-API prüfen)</Empty>;

  const pick = (id: string) => setSelected(id);
  const doFocus = (id: string) => {
    setFocusId(id);
    setSelected(id);
    setMode("focus");
  };
  const selectedNode = selected ? idx.byId.get(selected) : undefined;
  const suggestions = q.data.nodes
    .filter((n) => !isRule(n) && n.rule_refs > 0)
    .sort((a, b) => b.rule_refs - a.rule_refs)
    .slice(0, 12);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <ObjectSearch nodes={q.data.nodes} onPick={doFocus} />
        <ToggleGroup type="single" variant="outline" size="sm" value={mode} onValueChange={(v) => v && setMode(v as typeof mode)}>
          <ToggleGroupItem value="focus" className="px-3"><Crosshair className="size-4" />Fokus</ToggleGroupItem>
          <ToggleGroupItem value="overview" className="px-3"><Network className="size-4" />Gesamt</ToggleGroupItem>
        </ToggleGroup>
        {mode === "overview" && (
          <ToggleGroup
            type="multiple"
            variant="outline"
            size="sm"
            value={[...types]}
            onValueChange={(v) => setTypes(new Set(v as NodeType[]))}
            aria-label="Objekttypen"
          >
            {ALL_TYPES.map((t) => {
              const Icon = TYPE_META[t].icon;
              return (
                <ToggleGroupItem key={t} value={t} className="px-2.5 text-xs" title={TYPE_META[t].plural}>
                  <Icon className="size-3.5" /> {TYPE_META[t].plural}
                </ToggleGroupItem>
              );
            })}
          </ToggleGroup>
        )}
        {mode === "focus" && focus && (
          <Badge variant="outline" className="gap-1.5 border-primary/40 py-1">
            <Crosshair className="size-3 text-primary" /> {focus.name}
            <button onClick={() => setFocusId(null)} aria-label="Fokus entfernen"><X className="size-3" /></button>
          </Badge>
        )}
        <span className="ml-auto text-xs text-muted-foreground">
          {q.data.nodes.length} Objekte · {q.data.edges.length} Beziehungen
        </span>
      </div>

      <div className="grid h-[calc(100vh-17rem)] min-h-[520px] gap-3 lg:grid-cols-[1fr_22rem]">
        <div className="relative overflow-hidden rounded-xl border bg-card/40">
          {mode === "focus" && !focus ? (
            <div className="flex h-full flex-col items-center justify-center gap-4 p-6 text-center">
              <Crosshair className="size-8 text-primary" />
              <div>
                <div className="font-medium">Objekt auswählen</div>
                <div className="text-sm text-muted-foreground">
                  Zeigt alle Regeln, die auf ein Objekt verweisen – auch indirekt über Gruppen.
                </div>
              </div>
              <div className="flex max-w-2xl flex-wrap justify-center gap-2">
                {suggestions.map((n) => {
                  const Icon = iconFor(n);
                  return (
                    <Button key={n.id} variant="outline" size="sm" onClick={() => doFocus(n.id)}>
                      <Icon /> {n.name}
                      <span className="text-xs text-muted-foreground">{n.rule_refs}</span>
                    </Button>
                  );
                })}
              </div>
            </div>
          ) : flow.nodes.length === 0 ? (
            <Empty>{focus ? "Keine Regel verweist auf dieses Objekt." : "Keine Objekte für die gewählten Typen."}</Empty>
          ) : (
            <ReactFlow
              key={`${mode}-${focusId}-${[...types].join()}`}
              nodes={flow.nodes}
              edges={flow.edges}
              nodeTypes={nodeTypes}
              colorMode={theme}
              fitView
              fitViewOptions={{ padding: 0.08, maxZoom: 1.2 }}
              minZoom={0.1}
              nodesConnectable={false}
              onNodeClick={(_, n) => n.data.node && pick(n.data.node.id)}
              onNodeDoubleClick={(_, n) => n.data.node && doFocus(n.data.node.id)}
              onPaneClick={() => setSelected(null)}
              proOptions={{ hideAttribution: true }}
              style={{ "--xy-background-color": "transparent", "--xy-minimap-background-color": "var(--card)" } as CSSProperties}
            >
              <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="var(--grid)" />
              <Controls showInteractive={false} />
              {mode === "overview" && <MiniMap pannable zoomable bgColor="var(--card)" className="!rounded-lg !border" maskColor="color-mix(in oklch, var(--background) 70%, transparent)" nodeColor="var(--muted-foreground)" />}
            </ReactFlow>
          )}
          <div className="pointer-events-none absolute bottom-3 left-14 text-[11px] text-muted-foreground">
            Klick: Details · Doppelklick: Fokus
          </div>
        </div>

        {selectedNode ? (
          <DetailPanel node={selectedNode} idx={idx} onPick={pick} onFocus={doFocus} onClose={() => setSelected(null)} />
        ) : (
          <Card className="hidden gap-3 lg:flex">
            <CardContent className="space-y-3 text-sm text-muted-foreground">
              <div className="font-medium text-foreground">Legende</div>
              {ALL_TYPES.map((t) => {
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
                Die Zahl am Objekt = Anzahl Regeln, die direkt darauf verweisen. „Alle …“-Knoten stehen für fehlende
                Einschränkungen (Any).
              </p>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
