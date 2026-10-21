import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router";
import { Empty, ErrorBox, Loading, StatusBadge, UsageBar, type Status } from "../components/ui";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { fmtBytes, fmtNumber, fmtRelative, fmtUptime } from "../lib/format";
import type { DashboardEntry, Firewall } from "../lib/types";

/** Status einer Datenquelle: Fehler, veraltet (> 3 Intervalle) oder ok. */
export function sourceStatus(at: string | null, error: string | null, intervalS: number, enabled = true): Status {
  if (!enabled) return "off";
  if (error) return "critical";
  if (!at) return "warning";
  return Date.now() - new Date(at).getTime() > intervalS * 3000 ? "warning" : "good";
}

export function SourceBadges({ fw }: { fw: Firewall }) {
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1">
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

export function DashboardPage() {
  const { user } = useAuth();
  const q = useQuery({
    queryKey: ["dashboard"],
    queryFn: () => api<DashboardEntry[]>("/api/dashboard"),
    refetchInterval: 30_000,
  });

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Übersicht</h1>
      <ErrorBox error={q.error} />
      {q.isPending && <Loading />}
      {q.data?.length === 0 && (
        <Empty>
          Noch keine Firewall angelegt.{" "}
          {user?.role === "admin" && (
            <Link to="/admin/firewalls" className="text-accent hover:underline">
              Jetzt hinzufügen
            </Link>
          )}
        </Empty>
      )}
      <div className="grid gap-4 md:grid-cols-2 2xl:grid-cols-3">
        {q.data?.map(({ firewall: fw, metrics, hits_24h, denied_24h, bytes_24h }) => (
          <Link
            key={fw.id}
            to={`/firewalls/${fw.id}`}
            className="block space-y-4 rounded-lg border border-line bg-surface p-4 transition-colors hover:border-accent/50"
          >
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <div className="truncate font-semibold">{fw.name}</div>
                <div className="truncate text-xs text-muted">
                  {fw.host} · {fw.model ?? "Modell unbekannt"} · {fw.firmware ?? "Firmware unbekannt"}
                </div>
              </div>
              {!fw.enabled && <span className="text-xs text-muted">deaktiviert</span>}
            </div>
            <SourceBadges fw={fw} />
            <div className="grid grid-cols-3 gap-3">
              <UsageBar label="CPU" percent={metrics.cpu_percent} />
              <UsageBar label="RAM" percent={metrics.memory_percent} />
              <UsageBar label="Disk" percent={metrics.disk_percent} />
            </div>
            <dl className="grid grid-cols-4 gap-2 border-t border-line pt-3 text-xs">
              <div>
                <dt className="text-ink-2">Verbindungen 24 h</dt>
                <dd className="font-medium">{fmtNumber(hits_24h)}</dd>
              </div>
              <div>
                <dt className="text-ink-2">Blockiert 24 h</dt>
                <dd className="font-medium">{fmtNumber(denied_24h)}</dd>
              </div>
              <div>
                <dt className="text-ink-2">Traffic 24 h</dt>
                <dd className="font-medium">{fmtBytes(bytes_24h)}</dd>
              </div>
              <div>
                <dt className="text-ink-2">Uptime</dt>
                <dd className="font-medium">{fmtUptime(metrics.uptime_ticks)}</dd>
              </div>
            </dl>
          </Link>
        ))}
      </div>
    </div>
  );
}
