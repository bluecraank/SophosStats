import { useQuery } from "@tanstack/react-query";
import { ArrowRight, Ban, Cpu, Gauge, HardDrive, MemoryStick, Network, Server, Timer } from "lucide-react";
import { Link } from "react-router";
import { Empty, ErrorBox, Loading, PageHeader, StatTile, StatusBadge, UsageBar, type Status } from "@/components/ui";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { fmtBytes, fmtNumber, fmtRelative, fmtUptime } from "@/lib/format";
import type { DashboardEntry, Firewall } from "@/lib/types";

/** Status einer Datenquelle: Fehler, veraltet (> 3 Intervalle) oder ok. */
export function sourceStatus(at: string | null, error: string | null, intervalS: number, enabled = true): Status {
  if (!enabled) return "off";
  if (error) return "critical";
  if (!at) return "warning";
  return Date.now() - new Date(at).getTime() > intervalS * 3000 ? "warning" : "good";
}

export function SourceBadges({ fw }: { fw: Firewall }) {
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1.5">
      <StatusBadge
        status={sourceStatus(fw.last_metrics_at, fw.last_metrics_error, fw.metrics_interval_s, fw.snmp_enabled)}
        label={`SNMP ${fmtRelative(fw.last_metrics_at)}`}
        title={fw.last_metrics_error ?? undefined}
      />
      <StatusBadge
        status={
          !fw.last_config_error && fw.last_config_warning
            ? "warning"
            : sourceStatus(fw.last_config_at, fw.last_config_error, fw.config_interval_s)
        }
        label={`API ${fmtRelative(fw.last_config_at)}`}
        title={fw.last_config_error ?? fw.last_config_warning ?? undefined}
      />
      <StatusBadge
        status={fw.last_log_at ? sourceStatus(fw.last_log_at, null, 600) : "warning"}
        label={`Syslog ${fmtRelative(fw.last_log_at)}`}
      />
    </div>
  );
}

function FirewallCard({ entry }: { entry: DashboardEntry }) {
  const { firewall: fw, metrics, hits_24h, denied_24h, bytes_24h } = entry;
  return (
    <Link to={`/firewalls/${fw.id}`} className="group block">
      <Card className="h-full gap-0 py-0 transition-all duration-200 group-hover:-translate-y-0.5 group-hover:border-primary/40 group-hover:shadow-glow">
        <CardContent className="space-y-5 p-5">
          <div className="flex items-start gap-3">
            <span className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
              <Server className="size-5" />
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="truncate font-semibold">{fw.name}</span>
                {!fw.enabled && <Badge variant="secondary">deaktiviert</Badge>}
              </div>
              <div className="truncate text-xs text-muted-foreground">
                {fw.host} · {fw.model ?? "Modell ?"} · {fw.firmware ?? "Firmware ?"}
              </div>
            </div>
            <ArrowRight className="size-4 text-muted-foreground transition-transform group-hover:translate-x-0.5 group-hover:text-primary" />
          </div>
          <SourceBadges fw={fw} />
          <div className="grid grid-cols-3 gap-4">
            <UsageBar label="CPU" percent={metrics.cpu_percent} />
            <UsageBar label="RAM" percent={metrics.memory_percent} />
            <UsageBar label="Disk" percent={metrics.disk_percent} />
          </div>
        </CardContent>
        <div className="grid grid-cols-4 divide-x border-t text-xs">
          {[
            ["Verbindungen", fmtNumber(hits_24h)],
            ["Blockiert", fmtNumber(denied_24h)],
            ["Traffic", fmtBytes(bytes_24h)],
            ["Uptime", fmtUptime(metrics.uptime_ticks)],
          ].map(([label, value]) => (
            <div key={label} className="px-3 py-2.5">
              <div className="text-muted-foreground">{label}</div>
              <div className="font-medium tabular-nums">{value}</div>
            </div>
          ))}
        </div>
      </Card>
    </Link>
  );
}

export function DashboardPage() {
  const { user } = useAuth();
  const q = useQuery({
    queryKey: ["dashboard"],
    queryFn: () => api<DashboardEntry[]>("/api/dashboard"),
    refetchInterval: 30_000,
  });
  const data = q.data ?? [];
  const sum = (f: (e: DashboardEntry) => number) => data.reduce((s, e) => s + f(e), 0);
  const avg = (key: string) => {
    const vals = data.map((e) => e.metrics[key]).filter((v): v is number => v != null);
    return vals.length ? vals.reduce((a, b) => a + b, 0) / vals.length : undefined;
  };

  return (
    <div className="space-y-6">
      <PageHeader title="Übersicht" description="Zustand aller Firewalls · letzte 24 Stunden" />
      <ErrorBox error={q.error} />
      {q.isPending && <Loading />}

      {data.length > 0 && (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <StatTile label="Firewalls" value={data.length} icon={Server} hint={`${data.filter((e) => e.firewall.enabled).length} aktiv`} />
          <StatTile label="Verbindungen 24 h" value={fmtNumber(sum((e) => e.hits_24h))} icon={Network} />
          <StatTile label="Blockiert 24 h" value={fmtNumber(sum((e) => e.denied_24h))} icon={Ban} />
          <StatTile label="Traffic 24 h" value={fmtBytes(sum((e) => e.bytes_24h))} icon={Gauge} hint={avg("cpu_percent") != null ? `Ø CPU ${avg("cpu_percent")!.toFixed(0)} %` : undefined} />
        </div>
      )}

      {data.length === 0 && !q.isPending && (
        <Empty>
          <div className="space-y-3">
            <div>Noch keine Firewall angelegt.</div>
            {user?.role === "admin" && (
              <Button asChild size="sm">
                <Link to="/admin/firewalls">Firewall hinzufügen</Link>
              </Button>
            )}
          </div>
        </Empty>
      )}

      <div className="grid gap-4 md:grid-cols-2 2xl:grid-cols-3">
        {data.map((entry) => (
          <FirewallCard key={entry.firewall.id} entry={entry} />
        ))}
      </div>
    </div>
  );
}

// Icons, die Detailseiten für dieselben Kennzahlen nutzen
export const METRIC_ICONS = { cpu: Cpu, memory: MemoryStick, disk: HardDrive, uptime: Timer };
