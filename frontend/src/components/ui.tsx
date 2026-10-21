import type { ReactNode } from "react";

export function Card({ title, actions, children, className = "" }: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`rounded-lg border border-line bg-surface ${className}`}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-line px-4 py-3">
          <h2 className="text-sm font-semibold text-ink">{title}</h2>
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function StatTile({ label, value, hint }: { label: string; value: ReactNode; hint?: ReactNode }) {
  return (
    <div className="rounded-lg border border-line bg-surface px-4 py-3">
      <div className="text-xs font-medium text-ink-2">{label}</div>
      <div className="mt-1 text-2xl font-semibold text-ink">{value}</div>
      {hint && <div className="mt-0.5 text-xs text-muted">{hint}</div>}
    </div>
  );
}

/** Auslastungsbalken: Statusfarbe ab 75 % / 90 %, immer mit Zahlenwert daneben. */
export function UsageBar({ label, percent }: { label: string; percent: number | undefined }) {
  const p = percent ?? 0;
  const color = p >= 90 ? "bg-critical" : p >= 75 ? "bg-warning" : "bg-accent";
  return (
    <div>
      <div className="mb-1 flex justify-between text-xs">
        <span className="text-ink-2">{label}</span>
        <span className="font-medium text-ink">{percent == null ? "–" : `${p.toFixed(0)} %`}</span>
      </div>
      <div className="h-1.5 rounded-full bg-surface-2">
        <div className={`h-1.5 rounded-full ${color}`} style={{ width: `${Math.min(100, p)}%` }} />
      </div>
    </div>
  );
}

export type Status = "good" | "warning" | "critical" | "off";

const STATUS_STYLE: Record<Status, { dot: string; icon: string }> = {
  good: { dot: "bg-good", icon: "✓" },
  warning: { dot: "bg-warning", icon: "!" },
  critical: { dot: "bg-critical", icon: "×" },
  off: { dot: "bg-muted", icon: "–" },
};

/** Status nie nur über Farbe: Punkt + Symbol + Text. */
export function StatusBadge({ status, label, title }: { status: Status; label: string; title?: string }) {
  const s = STATUS_STYLE[status];
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-ink-2" title={title}>
      <span className={`inline-flex size-4 items-center justify-center rounded-full text-[10px] font-bold text-white ${s.dot}`}>
        {s.icon}
      </span>
      {label}
    </span>
  );
}

export function Pill({ children, tone = "neutral" }: { children: ReactNode; tone?: "neutral" | "good" | "critical" | "accent" }) {
  const cls = {
    neutral: "bg-surface-2 text-ink-2",
    good: "bg-good/15 text-ink",
    critical: "bg-critical/15 text-ink",
    accent: "bg-accent/15 text-ink",
  }[tone];
  return <span className={`inline-block rounded px-1.5 py-0.5 text-xs ${cls}`}>{children}</span>;
}

export function Tabs<T extends string>({ tabs, value, onChange }: {
  tabs: { id: T; label: string }[];
  value: T;
  onChange: (id: T) => void;
}) {
  return (
    <div className="flex gap-1 overflow-x-auto border-b border-line" role="tablist">
      {tabs.map((t) => (
        <button
          key={t.id}
          role="tab"
          aria-selected={value === t.id}
          onClick={() => onChange(t.id)}
          className={`-mb-px cursor-pointer whitespace-nowrap border-b-2 px-3 py-2 text-sm ${
            value === t.id ? "border-accent font-medium text-ink" : "border-transparent text-ink-2 hover:text-ink"
          }`}
        >
          {t.label}
        </button>
      ))}
    </div>
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
    <div className="inline-flex rounded-md border border-line bg-surface p-0.5" role="group" aria-label="Zeitraum">
      {RANGES.map((r) => (
        <button
          key={r.hours}
          onClick={() => onChange(r.hours)}
          aria-pressed={value === r.hours}
          className={`cursor-pointer rounded px-2.5 py-1 text-xs ${
            value === r.hours ? "bg-accent text-accent-ink" : "text-ink-2 hover:bg-surface-2"
          }`}
        >
          {r.label}
        </button>
      ))}
    </div>
  );
}

export function ErrorBox({ error }: { error: unknown }) {
  if (!error) return null;
  const msg = error instanceof Error ? error.message : String(error);
  return (
    <div className="rounded-md border border-critical/40 bg-critical/10 px-3 py-2 text-sm text-ink" role="alert">
      {msg}
    </div>
  );
}

export function Loading() {
  return <div className="py-8 text-center text-sm text-muted">Lade …</div>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="py-8 text-center text-sm text-muted">{children}</div>;
}

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <label className="block">
      <span className="label">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-muted">{hint}</span>}
    </label>
  );
}
