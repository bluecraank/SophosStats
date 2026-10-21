import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  ClipboardCheck,
  FileText,
  History,
  ListTree,
  Network,
  RefreshCw,
  ScrollText,
  Settings2,
  Share2,
  TriangleAlert,
} from "lucide-react";
import { Link, useParams, useSearchParams } from "react-router";
import { toast } from "sonner";
import { LogTable } from "@/components/LogTable";
import { ErrorBox, Loading, PageHeader, Tabs } from "@/components/ui";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { Firewall } from "@/lib/types";
import { SourceBadges } from "./DashboardPage";
import { AuditTab } from "./firewall/AuditTab";
import { ChangesTab } from "./firewall/ChangesTab";
import { ConfigTab } from "./firewall/ConfigTab";
import { GraphTab } from "./firewall/GraphTab";
import { OverviewTab } from "./firewall/OverviewTab";
import { RulesTab } from "./firewall/RulesTab";
import { TrafficTab } from "./firewall/TrafficTab";

const TABS = [
  { id: "overview", label: "System", icon: Activity },
  { id: "traffic", label: "Interfaces", icon: Network },
  { id: "rules", label: "Regeln", icon: ListTree },
  { id: "audit", label: "Audit", icon: ClipboardCheck },
  { id: "graph", label: "Beziehungen", icon: Share2 },
  { id: "logs", label: "Logs", icon: ScrollText },
  { id: "config", label: "Konfiguration", icon: Settings2 },
  { id: "changes", label: "Änderungen", icon: History },
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
    onSuccess: () => {
      toast.success("Abruf angefordert", { description: "Neue Daten erscheinen in wenigen Sekunden." });
      setTimeout(() => qc.invalidateQueries({ queryKey: ["firewall", id] }), 8000);
    },
    onError: (e) => toast.error("Abruf fehlgeschlagen", { description: e.message }),
  });

  if (fw.isPending) return <Loading />;
  if (fw.error) return <ErrorBox error={fw.error} />;
  const f = fw.data;

  return (
    <div className="space-y-5">
      <PageHeader
        title={f.name}
        description={
          <div className="space-y-2">
            <div>
              {f.host} · {f.model ?? "Modell unbekannt"} · {f.firmware ?? "Firmware unbekannt"}
              {f.serial && ` · SN ${f.serial}`}
            </div>
            <SourceBadges fw={f} />
          </div>
        }
        actions={
          <>
            <Button variant="outline" asChild>
              <Link to={`/firewalls/${id}/report`}>
                <FileText /> Bericht
              </Link>
            </Button>
            {user?.role === "admin" && (
              <Button onClick={() => poll.mutate()} disabled={poll.isPending}>
                <RefreshCw className={poll.isPending ? "animate-spin" : ""} /> Jetzt abrufen
              </Button>
            )}
          </>
        }
      />
      {(f.last_metrics_error || f.last_config_error) && (
        <Alert variant="destructive">
          <TriangleAlert />
          <AlertTitle>Abruf fehlgeschlagen</AlertTitle>
          <AlertDescription>
            {f.last_metrics_error && <div><strong>SNMP:</strong> {f.last_metrics_error}</div>}
            {f.last_config_error && <div><strong>XML-API:</strong> {f.last_config_error}</div>}
          </AlertDescription>
        </Alert>
      )}
      {f.last_config_warning && (
        <Alert className="border-warning/40 bg-warning/5">
          <TriangleAlert className="text-warning" />
          <AlertTitle>Hinweis XML-API</AlertTitle>
          <AlertDescription>{f.last_config_warning}</AlertDescription>
        </Alert>
      )}
      <Tabs tabs={[...TABS]} value={tab} onChange={(t) => setParams({ tab: t }, { replace: true })} />
      {tab === "overview" && <OverviewTab fwId={id} />}
      {tab === "traffic" && <TrafficTab fwId={id} />}
      {tab === "rules" && <RulesTab fwId={id} />}
      {tab === "audit" && <AuditTab fwId={id} />}
      {tab === "graph" && <GraphTab fwId={id} />}
      {tab === "logs" && <LogTable fixed={{ firewall_id: id }} />}
      {tab === "config" && <ConfigTab fwId={id} />}
      {tab === "changes" && <ChangesTab fwId={id} />}
    </div>
  );
}
