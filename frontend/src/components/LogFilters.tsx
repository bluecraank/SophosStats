import { ListFilter, Plus, X } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Select, SelectContent, SelectGroup, SelectItem, SelectLabel, SelectTrigger, SelectValue } from "@/components/ui/select";
import { cn } from "@/lib/utils";

export type FilterOp =
  | "eq"
  | "ne"
  | "contains"
  | "not_contains"
  | "starts"
  | "gt"
  | "lt"
  | "cidr"
  | "not_cidr"
  | "exists"
  | "missing";

export interface LogFilterValue {
  field: string;
  op: FilterOp;
  value: string;
}

type Kind = "ip" | "number" | "text";

/** Bekannte Spalten – alles andere wird als Rohfeld des SFOS-Logs gefiltert. */
export const FIELDS: Record<string, { label: string; kind: Kind }> = {
  src_ip: { label: "Quell-IP", kind: "ip" },
  dst_ip: { label: "Ziel-IP", kind: "ip" },
  src_port: { label: "Quell-Port", kind: "number" },
  dst_port: { label: "Ziel-Port", kind: "number" },
  protocol: { label: "Protokoll", kind: "text" },
  user_name: { label: "Benutzer", kind: "text" },
  rule_name: { label: "Regel", kind: "text" },
  rule_id: { label: "Regel-ID", kind: "number" },
  log_type: { label: "Log-Typ", kind: "text" },
  log_subtype: { label: "Untertyp", kind: "text" },
  log_component: { label: "Komponente", kind: "text" },
  status: { label: "Status", kind: "text" },
  severity: { label: "Priorität", kind: "text" },
  message: { label: "Meldung", kind: "text" },
  sent_bytes: { label: "Bytes gesendet", kind: "number" },
  recv_bytes: { label: "Bytes empfangen", kind: "number" },
};

/** Rohfelder aus dem SFOS-Log, die einer bekannten Spalte entsprechen. */
export const RAW_TO_COLUMN: Record<string, string> = { fw_rule_id: "rule_id", fw_rule_name: "rule_name", priority: "severity" };

export const OP_LABEL: Record<FilterOp, string> = {
  eq: "ist",
  ne: "ist nicht",
  contains: "enthält",
  not_contains: "enthält nicht",
  starts: "beginnt mit",
  gt: "größer als",
  lt: "kleiner als",
  cidr: "in Subnetz",
  not_cidr: "nicht in Subnetz",
  exists: "ist vorhanden",
  missing: "fehlt",
};

const OPS: Record<Kind | "raw", FilterOp[]> = {
  ip: ["eq", "ne", "cidr", "not_cidr", "starts", "exists", "missing"],
  number: ["eq", "ne", "gt", "lt", "exists", "missing"],
  text: ["eq", "ne", "contains", "not_contains", "starts", "exists", "missing"],
  raw: ["eq", "ne", "contains", "not_contains", "starts", "gt", "lt", "cidr", "exists", "missing"],
};
const NO_VALUE: FilterOp[] = ["exists", "missing"];

export const fieldLabel = (f: string) => FIELDS[f]?.label ?? f;
const opsFor = (field: string) => OPS[FIELDS[field]?.kind ?? "raw"];

/** Negation eines Operators – für Strg+Klick ("ausschließen"). */
export const NEGATE: Partial<Record<FilterOp, FilterOp>> = { eq: "ne", contains: "not_contains", cidr: "not_cidr", exists: "missing" };

export function FilterChip({ f, onRemove, onToggle }: { f: LogFilterValue; onRemove: () => void; onToggle?: () => void }) {
  const negative = ["ne", "not_contains", "not_cidr", "missing"].includes(f.op);
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border py-1 pr-1 pl-2.5 text-xs",
        negative ? "border-critical/40 bg-critical/10" : "border-primary/40 bg-primary/10",
      )}
    >
      <span className="text-muted-foreground">{fieldLabel(f.field)}</span>
      <button
        type="button"
        onClick={onToggle}
        disabled={!onToggle}
        className="font-medium hover:underline disabled:no-underline"
        title={onToggle ? "Klicken zum Umkehren" : undefined}
      >
        {OP_LABEL[f.op]}
      </button>
      {!NO_VALUE.includes(f.op) && <span className="max-w-48 truncate font-mono">{f.value}</span>}
      <button type="button" onClick={onRemove} className="rounded p-0.5 hover:bg-background/60" aria-label="Filter entfernen">
        <X className="size-3" />
      </button>
    </span>
  );
}

export function AddFilter({ rawFields, onAdd }: { rawFields: string[]; onAdd: (f: LogFilterValue) => void }) {
  const [open, setOpen] = useState(false);
  const [field, setField] = useState("src_ip");
  const [op, setOp] = useState<FilterOp>("eq");
  const [value, setValue] = useState("");
  const [custom, setCustom] = useState("");
  const effectiveField = field === "__custom" ? custom.trim() : field;
  const ops = opsFor(effectiveField);
  const needsValue = !NO_VALUE.includes(op);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!effectiveField || (needsValue && !value.trim())) return;
    onAdd({ field: effectiveField, op, value: needsValue ? value.trim() : "" });
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
                setField(v);
                if (!opsFor(v === "__custom" ? custom : v).includes(op)) setOp("eq");
              }}
            >
              <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
              <SelectContent className="max-h-80">
                <SelectGroup>
                  <SelectLabel>Standardfelder</SelectLabel>
                  {Object.entries(FIELDS).map(([k, v]) => <SelectItem key={k} value={k}>{v.label}</SelectItem>)}
                </SelectGroup>
                {rawFields.length > 0 && (
                  <SelectGroup>
                    <SelectLabel>Felder aus den Logs</SelectLabel>
                    {rawFields.map((k) => <SelectItem key={k} value={k}>{k}</SelectItem>)}
                  </SelectGroup>
                )}
                <SelectGroup>
                  <SelectItem value="__custom">Anderes Feld …</SelectItem>
                </SelectGroup>
              </SelectContent>
            </Select>
            {field === "__custom" && (
              <Input placeholder="Feldname, z.B. app_name" value={custom} onChange={(e) => setCustom(e.target.value)} />
            )}
          </div>
          <div className="space-y-1.5">
            <Label>Bedingung</Label>
            <Select value={op} onValueChange={(v) => setOp(v as FilterOp)}>
              <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
              <SelectContent>
                {ops.map((o) => <SelectItem key={o} value={o}>{OP_LABEL[o]}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
          {needsValue && (
            <div className="space-y-1.5">
              <Label>Wert</Label>
              <Input
                autoFocus
                className="font-mono"
                placeholder={op === "cidr" || op === "not_cidr" ? "10.0.0.0/8" : FIELDS[effectiveField]?.kind === "number" ? "443" : "Wert"}
                value={value}
                onChange={(e) => setValue(e.target.value)}
              />
            </div>
          )}
          <Button className="w-full" disabled={!effectiveField || (needsValue && !value.trim())}>
            <Plus /> Hinzufügen
          </Button>
        </form>
      </PopoverContent>
    </Popover>
  );
}
