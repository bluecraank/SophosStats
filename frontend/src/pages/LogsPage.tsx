import { useQuery } from "@tanstack/react-query";
import { LogTable } from "../components/LogTable";
import { api } from "../lib/api";
import type { Firewall } from "../lib/types";

export function LogsPage() {
  const firewalls = useQuery({ queryKey: ["firewalls"], queryFn: () => api<Firewall[]>("/api/firewalls") });
  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Logs</h1>
      <LogTable firewalls={firewalls.data ?? []} />
    </div>
  );
}
