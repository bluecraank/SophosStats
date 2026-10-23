import { useQuery } from "@tanstack/react-query";
import { Globe, Monitor, Server } from "lucide-react";
import { useEffect, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

export interface HostSuggestion {
  hostname: string;
  ip: string;
  source: "rdns" | "object" | "dns";
}

const SOURCE: Record<HostSuggestion["source"], { label: string; icon: typeof Globe }> = {
  rdns: { label: "DNS", icon: Monitor },
  object: { label: "Firewall-Objekt", icon: Server },
  dns: { label: "aufgelöst", icon: Globe },
};

function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

/**
 * Eingabefeld mit Hostnamen-Vorschlägen: "EDV-" zeigt alle bekannten Hosts mit diesem Anfang (per Reverse-DNS
 * gelernt oder als Firewall-Objekt), "10.50." alle bekannten Hosts in diesem Bereich.
 */
export function HostInput({
  value,
  onChange,
  onPick,
  onEnter,
  placeholder,
  className,
  icon,
  required,
}: {
  value: string;
  onChange: (v: string) => void;
  onPick: (s: HostSuggestion) => void;
  onEnter?: () => void;
  placeholder?: string;
  className?: string;
  icon?: ReactNode;
  required?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const box = useRef<HTMLDivElement>(null);
  const term = useDebounced(value.trim(), 200);
  const q = useQuery({
    queryKey: ["host-suggest", term],
    queryFn: () => api<HostSuggestion[]>("/api/hosts/suggest", { params: { q: term } }),
    enabled: open && term.length >= 2,
    staleTime: 60_000,
  });
  const items = q.data ?? [];

  useEffect(() => {
    const close = (e: MouseEvent) => box.current && !box.current.contains(e.target as Node) && setOpen(false);
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, []);

  const pick = (s: HostSuggestion) => {
    setOpen(false);
    onPick(s);
  };
  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown" && items.length) {
      e.preventDefault();
      setOpen(true);
      setActive((a) => (a + 1) % items.length);
    } else if (e.key === "ArrowUp" && items.length) {
      e.preventDefault();
      setActive((a) => (a - 1 + items.length) % items.length);
    } else if (e.key === "Enter") {
      if (open && items[active] && term.length >= 2) {
        e.preventDefault();
        pick(items[active]);
      } else {
        setOpen(false);
        onEnter?.();
      }
    } else if (e.key === "Escape") {
      setOpen(false);
    }
  };

  return (
    <div ref={box} className={cn("relative", className)}>
      {icon}
      <Input
        className={cn("font-mono", icon && "pl-8")}
        placeholder={placeholder}
        value={value}
        required={required}
        autoComplete="off"
        onChange={(e) => {
          onChange(e.target.value);
          setOpen(true);
          setActive(0);
        }}
        onFocus={() => setOpen(true)}
        onKeyDown={onKeyDown}
        role="combobox"
        aria-expanded={open && items.length > 0}
      />
      {open && term.length >= 2 && items.length > 0 && (
        <ul
          role="listbox"
          className="absolute top-full left-0 z-50 mt-1 max-h-80 w-max max-w-[36rem] min-w-full overflow-auto rounded-lg border bg-popover p-1 shadow-xl"
        >
          {items.map((s, i) => {
            const src = SOURCE[s.source];
            return (
              <li
                key={`${s.hostname}-${s.ip}`}
                role="option"
                aria-selected={i === active}
                onMouseEnter={() => setActive(i)}
                onMouseDown={(e) => {
                  e.preventDefault();
                  pick(s);
                }}
                className={cn(
                  "flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm",
                  i === active && "bg-accent text-accent-foreground",
                )}
              >
                <src.icon className="size-4 shrink-0 text-muted-foreground" />
                <span className="min-w-0 flex-1 truncate font-medium" title={s.hostname}>{s.hostname}</span>
                <span className="font-mono text-xs text-muted-foreground">{s.ip}</span>
                <span className="shrink-0 pl-2 text-right text-[10px] text-muted-foreground/70">{src.label}</span>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

/** Hostnamen zu einer Menge IPs (für die Anzeige unter IPs in Tabellen). */
export function useHostNames(ips: (string | null | undefined)[]): Record<string, string> {
  const unique = [...new Set(ips.filter((x): x is string => !!x))].sort().slice(0, 300);
  const q = useQuery({
    queryKey: ["host-lookup", unique.join(",")],
    queryFn: () => api<Record<string, string>>("/api/hosts/lookup", { params: { ip: unique } }),
    enabled: unique.length > 0,
    staleTime: 10 * 60_000,
  });
  return q.data ?? {};
}
