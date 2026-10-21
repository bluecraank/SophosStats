import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams, useSearchParams } from "react-router";
import { LogTable } from "../components/LogTable";
import { ErrorBox, Loading, Tabs } from "../components/ui";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import type { Firewall } from "../lib/types";
import { SourceBadges } from "./DashboardPage";
import { ChangesTab } from "./firewall/ChangesTab";
import { ConfigTab } from "./firewall/ConfigTab";
import { OverviewTab } from "./firewall/OverviewTab";
import { RulesTab } from "./firewall/RulesTab";
import { TrafficTab } from "./firewall/TrafficTab";

const TABS = [
  { id: "overview", label: "System" },
  { id: "traffic", label: "Interfaces" },
  { id: "rules", label: "Regeln" },
  { id: "logs", label: "Logs" },
  { id: "config", label: "Konfiguration" },
  { id: "changes", label: "Änderungen" },
] as const;
type TabId = (typeof TABS)[number]["id"];

export function FirewallPage() {
  const id = Number(useParams().id);
  const [params, setParams] = useSearchParams();
  const tab = (params.get("tab") as TabId) || "overview";
  const { user } = useAuth();
  const qc = useQueryClient();

  const fw = useQuery({
    queryKey: ["firewall", id],
    queryFn: () => api<Firewall>(`/api/firewalls/${id}`),
    refetchInterval: 30_000,
  });
  const poll = useMutation({
    mutationFn: () => api(`/api/firewalls/${id}/poll`, { method: "POST" }),
    onSuccess: () => setTimeout(() => qc.invalidateQueries({ queryKey: ["firewall", id] }), 8000),
  });

  if (fw.isPending) return <Loading />;
  if (fw.error) return <ErrorBox error={fw.error} />;
  const f = fw.data;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">{f.name}</h1>
          <div className="text-sm text-ink-2">
            {f.host} · {f.model ?? "Modell unbekannt"} · {f.firmware ?? "Firmware unbekannt"}
            {f.serial && ` · SN ${f.serial}`}
          </div>
          <div className="mt-2">
            <SourceBadges fw={f} />
          </div>
        </div>
        {user?.role === "admin" && (
          <button className="btn-secondary" onClick={() => poll.mutate()} disabled={poll.isPending}>
            {poll.isSuccess ? "Abruf angefordert" : "Jetzt abrufen"}
          </button>
        )}
      </div>
      {(f.last_metrics_error || f.last_config_error) && (
        <div className="space-y-1 rounded-md border border-critical/40 bg-critical/10 px-3 py-2 text-sm">
          {f.last_metrics_error && <div><strong>SNMP:</strong> {f.last_metrics_error}</div>}
          {f.last_config_error && <div><strong>XML-API:</strong> {f.last_config_error}</div>}
        </div>
      )}
      {f.last_config_warning && (
        <div className="rounded-md border border-warning/50 bg-warning/10 px-3 py-2 text-sm" role="status">
          <strong>Hinweis XML-API:</strong> {f.last_config_warning}
        </div>
      )}
      <Tabs tabs={[...TABS]} value={tab} onChange={(t) => setParams({ tab: t }, { replace: true })} />
      {tab === "overview" && <OverviewTab fwId={id} />}
      {tab === "traffic" && <TrafficTab fwId={id} />}
      {tab === "rules" && <RulesTab fwId={id} />}
      {tab === "logs" && <LogTable fixed={{ firewall_id: id }} />}
      {tab === "config" && <ConfigTab fwId={id} />}
      {tab === "changes" && <ChangesTab fwId={id} />}
    </div>
  );
}
