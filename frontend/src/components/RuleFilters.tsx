import { ListFilter, Plus, X } from "lucide-react";
import { useMemo, useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import type { Rule } from "@/lib/types";
import { cn } from "@/lib/utils";

/** Regel-Filter (clientseitig – alle Regeln einer Firewall sind ohnehin geladen). */
export interface RuleFilter {
  field: RuleField;
  op: RuleOp;
  value: string;
}

type Kind = "enum" | "list" | "text" | "number" | "age";
type RuleField =
  | "name"
  | "action"
  | "status"
  | "logging"
  | "group"
  | "policy_type"
  | "source_zones"
  | "destination_zones"
  | "source_networks"
  | "destination_networks"
  | "services"
  | "hits"
  | "last_seen";
type RuleOp = "eq" | "ne" | "has" | "has_not" | "is_any" | "not_any" | "contains" | "not_contains" | "gt" | "lt" | "older" | "never";

const FIELDS: Record<RuleField, { label: string; kind: Kind }> = {
  name: { label: "Name/Beschreibung", kind: "text" },
  action: { label: "Aktion", kind: "enum" },
  status: { label: "Status", kind: "enum" },
  logging: { label: "Logging", kind: "enum" },
  group: { label: "Gruppe", kind: "enum" },
  policy_type: { label: "Regeltyp", kind: "enum" },
  source_zones: { label: "Quell-Zone", kind: "list" },
  destination_zones: { label: "Ziel-Zone", kind: "list" },
  source_networks: { label: "Quelle", kind: "list" },
  destination_networks: { label: "Ziel", kind: "list" },
  services: { label: "Dienst", kind: "list" },
  hits: { label: "Treffer (Zeitraum)", kind: "number" },
  last_seen: { label: "Zuletzt genutzt", kind: "age" },
};

const OP_LABEL: Record<RuleOp, string> = {
  eq: "ist",
  ne: "ist nicht",
  has: "enthält",
  has_not: "enthält nicht",
  is_any: "ist „Alle“ (Any)",
  not_any: "ist eingeschränkt",
  contains: "enthält",
  not_contains: "enthält nicht",
  gt: "größer als",
  lt: "kleiner als",
  older: "älter als (Tage)",
  never: "nie",
};
const OPS: Record<Kind, RuleOp[]> = {
  enum: ["eq", "ne"],
  list: ["has", "has_not", "is_any", "not_any"],
  text: ["contains", "not_contains"],
  number: ["gt", "lt", "eq"],
  age: ["older", "never"],
};
const NO_VALUE: RuleOp[] = ["is_any", "not_any", "never"];
const NEGATIVE: RuleOp[] = ["ne", "has_not", "not_contains", "never", "older", "is_any"];

const ENUM_VALUE: Partial<Record<RuleField, (r: Rule) => string>> = {
  action: (r) => r.action ?? "–",
  status: (r) => (r.enabled ? "aktiv" : "deaktiviert"),
  logging: (r) => (r.log_traffic ? "an" : "aus"),
  group: (r) => r.group ?? "(keine)",
  policy_type: (r) => r.policy_type ?? "–",
};

export function matchRule(r: Rule, f: RuleFilter): boolean {
  const kind = FIELDS[f.field].kind;
  const v = f.value.trim().toLowerCase();
  if (kind === "enum") {
    const actual = ENUM_VALUE[f.field]!(r).toLowerCase();
    return f.op === "eq" ? actual === v : actual !== v;
  }
  if (kind === "list") {
    const items = (r[f.field as keyof Rule] as string[]).map((x) => x.toLowerCase());
    if (f.op === "is_any") return items.length === 0;
    if (f.op === "not_any") return items.length > 0;
    const has = items.includes(v);
    return f.op === "has" ? has : !has;
  }
  if (kind === "text") {
    const hay = `${r.name} ${r.description ?? ""}`.toLowerCase();
    return f.op === "contains" ? hay.includes(v) : !hay.includes(v);
  }
  if (kind === "number") {
    const n = r.usage?.hits ?? 0;
    const x = Number(v);
    return f.op === "gt" ? n > x : f.op === "lt" ? n < x : n === x;
  }
  // age
  if (f.op === "never") return !r.last_seen_ever;
  if (!r.last_seen_ever) return true; // nie genutzt ist auch "älter als N Tage"
  return Date.now() - new Date(r.last_seen_ever).getTime() > Number(v) * 86400_000;
}

/** Häufige Fragen als Ein-Klick-Filter. */
export const PRESETS: { label: string; filters: RuleFilter[] }[] = [
  { label: "Ungenutzt (30 T)", filters: [{ field: "status", op: "eq", value: "aktiv" }, { field: "last_seen", op: "older", value: "30" }] },
  { label: "Blockierend", filters: [{ field: "action", op: "ne", value: "Accept" }] },
  { label: "Quelle Any", filters: [{ field: "action", op: "eq", value: "Accept" }, { field: "source_networks", op: "is_any", value: "" }] },
  { label: "Alle Dienste", filters: [{ field: "action", op: "eq", value: "Accept" }, { field: "services", op: "is_any", value: "" }] },
  { label: "Ohne Logging", filters: [{ field: "status", op: "eq", value: "aktiv" }, { field: "logging", op: "eq", value: "aus" }] },
  { label: "Deaktiviert", filters: [{ field: "status", op: "eq", value: "deaktiviert" }] },
];

export function RuleFilterChip({ f, onRemove }: { f: RuleFilter; onRemove: () => void }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border py-1 pr-1 pl-2.5 text-xs",
        NEGATIVE.includes(f.op) ? "border-critical/40 bg-critical/10" : "border-primary/40 bg-primary/10",
      )}
    >
      <span className="text-muted-foreground">{FIELDS[f.field].label}</span>
      <span className="font-medium">{OP_LABEL[f.op]}</span>
      {!NO_VALUE.includes(f.op) && <span className="max-w-48 truncate font-mono">{f.value}</span>}
      <button type="button" onClick={onRemove} className="rounded p-0.5 hover:bg-background/60" aria-label="Filter entfernen">
        <X className="size-3" />
      </button>
    </span>
  );
}

export function AddRuleFilter({ rules, onAdd }: { rules: Rule[]; onAdd: (f: RuleFilter) => void }) {
  const [open, setOpen] = useState(false);
  const [field, setField] = useState<RuleField>("source_zones");
  const [op, setOp] = useState<RuleOp>("has");
  const [value, setValue] = useState("");
  const kind = FIELDS[field].kind;
  const needsValue = !NO_VALUE.includes(op);

  // Wertvorschläge aus den vorhandenen Regeln
  const suggestions = useMemo(() => {
    const set = new Set<string>();
    for (const r of rules) {
      if (kind === "enum") set.add(ENUM_VALUE[field]!(r));
      if (kind === "list") (r[field as keyof Rule] as string[]).forEach((x) => set.add(x));
    }
    return [...set].sort((a, b) => a.localeCompare(b));
  }, [rules, field, kind]);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (needsValue && !value.trim()) return;
    onAdd({ field, op, value: needsValue ? value.trim() : "" });
    setValue("");
    setOpen(false);
  };

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm" className="h-9">
          <ListFilter /> Filter hinzufügen
        </Button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-80">
        <form className="space-y-3" onSubmit={submit}>
          <div className="space-y-1.5">
            <Label>Feld</Label>
            <Select
              value={field}
              onValueChange={(v) => {
                const f = v as RuleField;
                setField(f);
                setOp(OPS[FIELDS[f].kind][0]);
                setValue("");
              }}
            >
              <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
              <SelectContent>
                {(Object.keys(FIELDS) as RuleField[]).map((k) => <SelectItem key={k} value={k}>{FIELDS[k].label}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label>Bedingung</Label>
            <Select value={op} onValueChange={(v) => setOp(v as RuleOp)}>
              <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
              <SelectContent>
                {OPS[kind].map((o) => <SelectItem key={o} value={o}>{OP_LABEL[o]}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
          {needsValue && (
            <div className="space-y-1.5">
              <Label>Wert</Label>
              {kind === "enum" && suggestions.length > 0 ? (
                <Select value={value} onValueChange={setValue}>
                  <SelectTrigger className="w-full"><SelectValue placeholder="Auswählen …" /></SelectTrigger>
                  <SelectContent>
                    {suggestions.map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
                  </SelectContent>
                </Select>
              ) : (
                <>
                  <Input
                    autoFocus
                    list="rule-filter-values"
                    inputMode={kind === "number" || kind === "age" ? "numeric" : undefined}
                    placeholder={kind === "age" ? "30" : kind === "number" ? "0" : "Name des Objekts"}
                    value={value}
                    onChange={(e) => setValue(e.target.value)}
                  />
                  <datalist id="rule-filter-values">
                    {suggestions.slice(0, 500).map((s) => <option key={s} value={s} />)}
                  </datalist>
                </>
              )}
            </div>
          )}
          <Button className="w-full" disabled={needsValue && !value.trim()}>
            <Plus /> Hinzufügen
          </Button>
        </form>
      </PopoverContent>
    </Popover>
  );
}
