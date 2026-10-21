/** Anwendungsbausteine auf Basis der shadcn/ui-Komponenten (src/components/ui/*). */
import { AlertCircle, Inbox, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Card as UiCard, CardAction, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs as UiTabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { cn } from "@/lib/utils";

export function Card({
  title,
  actions,
  children,
  className = "",
  icon: Icon,
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  icon?: LucideIcon;
}) {
  return (
    <UiCard className={cn("gap-4 py-5", className)}>
      {(title || actions) && (
        <CardHeader className="px-5">
          <CardTitle className="flex items-center gap-2 text-sm font-semibold">
            {Icon && <Icon className="size-4 text-primary" />}
            {title}
          </CardTitle>
          {actions && <CardAction className="flex items-center gap-2">{actions}</CardAction>}
        </CardHeader>
      )}
      <CardContent className="px-5">{children}</CardContent>
    </UiCard>
  );
}

export function StatTile({
  label,
  value,
  hint,
  icon: Icon,
  children,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  icon?: LucideIcon;
  children?: ReactNode;
}) {
  return (
    <UiCard className="relative gap-1 overflow-hidden px-4 py-4">
      <div className="flex items-center justify-between text-xs font-medium text-muted-foreground">
        {label}
        {Icon && (
          <span className="flex size-7 items-center justify-center rounded-md bg-primary/10 text-primary">
            <Icon className="size-4" />
          </span>
        )}
      </div>
      <div className="text-2xl font-semibold tracking-tight">{value}</div>
      {hint && <div className="text-xs text-muted-foreground">{hint}</div>}
      {children}
    </UiCard>
  );
}

/** Auslastungsbalken: Statusfarbe ab 75 % / 90 %, Zahlenwert immer daneben. */
export function UsageBar({ label, percent }: { label: string; percent: number | undefined }) {
  const p = percent ?? 0;
  const color = p >= 90 ? "bg-critical" : p >= 75 ? "bg-warning" : "bg-primary";
  return (
    <div>
      <div className="mb-1.5 flex justify-between text-xs">
        <span className="text-muted-foreground">{label}</span>
        <span className="font-medium tabular-nums">{percent == null ? "–" : `${p.toFixed(0)} %`}</span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-muted">
        <div
          className={cn("h-full rounded-full transition-[width] duration-500", color, p < 75 && "shadow-glow")}
          style={{ width: `${Math.min(100, p)}%` }}
        />
      </div>
    </div>
  );
}

export type Status = "good" | "warning" | "critical" | "off";

const STATUS_STYLE: Record<Status, { dot: string; ring: string }> = {
  good: { dot: "bg-good", ring: "shadow-[0_0_8px_var(--good)]" },
  warning: { dot: "bg-warning", ring: "shadow-[0_0_8px_var(--warning)]" },
  critical: { dot: "bg-critical", ring: "shadow-[0_0_8px_var(--critical)]" },
  off: { dot: "bg-muted-foreground/50", ring: "" },
};
const STATUS_TEXT: Record<Status, string> = { good: "OK", warning: "Warnung", critical: "Fehler", off: "aus" };

/** Status nie nur über Farbe: leuchtender Punkt + Text (+ Statuswort für Screenreader). */
export function StatusBadge({ status, label, title }: { status: Status; label: string; title?: string }) {
  const s = STATUS_STYLE[status];
  return (
    <span className="inline-flex items-center gap-2 text-xs text-muted-foreground" title={title}>
      <span className={cn("size-2 shrink-0 rounded-full", s.dot, s.ring, status === "good" && "animate-pulse")} />
      <span className="sr-only">{STATUS_TEXT[status]}:</span>
      {label}
    </span>
  );
}

export function Pill({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: "neutral" | "good" | "critical" | "accent";
}) {
  const cls = {
    neutral: "",
    good: "border-good/30 bg-good/10 text-foreground",
    critical: "border-critical/30 bg-critical/10 text-foreground",
    accent: "border-primary/30 bg-primary/10 text-foreground",
  }[tone];
  return (
    <Badge variant={tone === "neutral" ? "secondary" : "outline"} className={cn("font-normal", cls)}>
      {children}
    </Badge>
  );
}

export function Tabs<T extends string>({
  tabs,
  value,
  onChange,
}: {
  tabs: { id: T; label: string; icon?: LucideIcon }[];
  value: T;
  onChange: (id: T) => void;
}) {
  return (
    <UiTabs value={value} onValueChange={(v) => onChange(v as T)}>
      <TabsList className="h-auto max-w-full flex-wrap justify-start">
        {tabs.map((t) => (
          <TabsTrigger key={t.id} value={t.id} className="gap-1.5 px-3">
            {t.icon && <t.icon className="size-4" />}
            {t.label}
          </TabsTrigger>
        ))}
      </TabsList>
    </UiTabs>
  );
}

export const RANGES = [
  { hours: 1, label: "1 h" },
  { hours: 6, label: "6 h" },
  { hours: 24, label: "24 h" },
  { hours: 168, label: "7 T" },
  { hours: 720, label: "30 T" },
  { hours: 2160, label: "90 T" },
];

export function RangeSelect({ value, onChange }: { value: number; onChange: (h: number) => void }) {
  return (
    <ToggleGroup
      type="single"
      variant="outline"
      size="sm"
      value={String(value)}
      onValueChange={(v) => v && onChange(Number(v))}
      aria-label="Zeitraum"
    >
      {RANGES.map((r) => (
        <ToggleGroupItem key={r.hours} value={String(r.hours)} className="px-2.5 text-xs data-[state=on]:text-primary">
          {r.label}
        </ToggleGroupItem>
      ))}
    </ToggleGroup>
  );
}

export function ErrorBox({ error }: { error: unknown }) {
  if (!error) return null;
  const msg = error instanceof Error ? error.message : String(error);
  return (
    <Alert variant="destructive">
      <AlertCircle />
      <AlertDescription>{msg}</AlertDescription>
    </Alert>
  );
}

export function Loading() {
  return (
    <div className="space-y-3 py-2" aria-label="Lade …" role="status">
      <Skeleton className="h-8 w-1/3" />
      <Skeleton className="h-24 w-full" />
      <Skeleton className="h-24 w-full" />
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-2 rounded-xl border border-dashed py-10 text-center text-sm text-muted-foreground">
      <Inbox className="size-6 opacity-60" />
      <div>{children}</div>
    </div>
  );
}

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <label className="block">
      <span className="label">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-muted-foreground">{hint}</span>}
    </label>
  );
}

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {description && <div className="mt-1 text-sm text-muted-foreground">{description}</div>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}
