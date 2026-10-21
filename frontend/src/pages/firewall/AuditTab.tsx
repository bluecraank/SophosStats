import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  BadgeCheck,
  ChevronDown,
  EyeOff,
  FileWarning,
  Layers2,
  PowerOff,
  ShieldAlert,
  TriangleAlert,
  Undo2,
  Unplug,
  type LucideIcon,
} from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { Empty, ErrorBox, Loading, StatusBadge, type Status } from "@/components/ui";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { fmtDate } from "@/lib/format";
import type { AuditFinding, AuditResult, FindingKind } from "@/lib/types";
import { cn } from "@/lib/utils";

export const KIND_LABEL: Record<FindingKind, string> = {
  shadowed: "Verdeckt",
  redundant: "Redundant",
  too_broad: "Zu breit",
  unused: "Ungenutzt",
  no_logging: "Ohne Logging",
  disabled: "Deaktiviert",
};

const KIND_ICON: Record<FindingKind, LucideIcon> = {
  shadowed: EyeOff,
  redundant: Layers2,
  too_broad: ShieldAlert,
  unused: Unplug,
  no_logging: FileWarning,
  disabled: PowerOff,
};

const KIND_HINT: Record<FindingKind, string> = {
  shadowed: "Eine Regel weiter oben greift zuerst mit anderer Aktion – diese Regel wirkt nie.",
  redundant: "Eine Regel weiter oben erlaubt/blockiert bereits dasselbe – kann entfernt werden.",
  too_broad: "Erlaubende Regel mit Any als Quelle, Ziel oder Dienst. Je mehr Seiten offen sind, desto höher die Schwere.",
  unused: "Kein Treffer im gewählten Zeitraum – Kandidat zum Deaktivieren.",
  no_logging: "Ohne „Log firewall traffic“ sind Nutzung und ungenutzte Regeln nicht erkennbar.",
  disabled: "Deaktivierte Regeln machen das Regelwerk unübersichtlich.",
};

export const SEVERITY: Record<AuditFinding["severity"], { status: Status; label: string }> = {
  high: { status: "critical", label: "Hoch" },
  medium: { status: "warning", label: "Mittel" },
  low: { status: "off", label: "Niedrig" },
  info: { status: "off", label: "Info" },
};

const KINDS: FindingKind[] = ["shadowed", "redundant", "too_broad", "unused", "no_logging", "disabled"];

const EXPIRY = [
  { value: "none", label: "Unbegrenzt (bis die Regel geändert wird)" },
  { value: "30", label: "30 Tage" },
  { value: "90", label: "90 Tage" },
  { value: "180", label: "180 Tage" },
  { value: "365", label: "1 Jahr" },
];

function AckDialog({ fwId, finding, onClose }: { fwId: number; finding: AuditFinding | null; onClose: () => void }) {
  const qc = useQueryClient();
  const [reason, setReason] = useState("");
  const [expiry, setExpiry] = useState("none");
  const ack = useMutation({
    mutationFn: () =>
      api(`/api/firewalls/${fwId}/audit/acks`, {
        method: "POST",
        body: {
          kind: finding!.kind,
          rule: finding!.rule,
          reason,
          expires_days: expiry === "none" ? null : Number(expiry),
        },
      }),
    onSuccess: () => {
      toast.success("Befund akzeptiert", { description: finding!.rule });
      qc.invalidateQueries({ queryKey: ["audit", fwId] });
      setReason("");
      setExpiry("none");
      onClose();
    },
  });

  return (
    <Dialog open={!!finding} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Befund als okay markieren</DialogTitle>
          <DialogDescription>
            {finding && (
              <>
                <strong>{KIND_LABEL[finding.kind]}</strong> · {finding.rule} – {finding.message}
              </>
            )}
          </DialogDescription>
        </DialogHeader>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            ack.mutate();
          }}
        >
          <ErrorBox error={ack.error} />
          <div className="space-y-2">
            <Label htmlFor="ack-reason">Begründung (erscheint im Bericht)</Label>
            <Textarea
              id="ack-reason"
              placeholder="z.B. Gastnetz darf ins Internet – Einschränkung über Web-Filter und IPS"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              minLength={5}
              required
              rows={4}
            />
          </div>
          <div className="space-y-2">
            <Label>Gültigkeit</Label>
            <Select value={expiry} onValueChange={setExpiry}>
              <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
              <SelectContent>
                {EXPIRY.map((e) => <SelectItem key={e.value} value={e.value}>{e.label}</SelectItem>)}
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              Wird die Regel geändert, verfällt die Akzeptanz automatisch und der Befund erscheint wieder.
            </p>
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>Abbrechen</Button>
            <Button disabled={ack.isPending || reason.trim().length < 5}>
              <BadgeCheck /> Akzeptieren
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function FindingRow({ f, onAck, onRevoke }: { f: AuditFinding; onAck?: () => void; onRevoke?: () => void }) {
  const Icon = KIND_ICON[f.kind];
  return (
    <li className="flex flex-wrap items-start gap-x-4 gap-y-2 border-t px-4 py-3 first:border-t-0">
      <span className="w-20 shrink-0 pt-0.5">
        <StatusBadge status={f.ack ? "good" : SEVERITY[f.severity].status} label={f.ack ? "Akzeptiert" : SEVERITY[f.severity].label} />
      </span>
      <span className="flex w-32 shrink-0 items-center gap-1.5 text-xs text-muted-foreground">
        <Icon className="size-3.5" />
        {KIND_LABEL[f.kind]}
      </span>
      <span className="min-w-0 flex-1 space-y-1">
        <span className="block text-sm font-medium">
          {f.position != null && <span className="text-muted-foreground">#{f.position + 1} </span>}
          {f.rule}
        </span>
        <span className="block text-sm text-muted-foreground">{f.message}</span>
        {f.profile && (
          <span className="block text-xs text-muted-foreground/80">
            Tatsächlich genutzt: {f.profile.sources} Quellen · {f.profile.destinations} Ziele · {f.profile.ports} Zielports
            – Details im Tab „Regeln“
          </span>
        )}
        {f.ack && (
          <span className="mt-1 block rounded-md border border-good/25 bg-good/5 px-3 py-2 text-xs">
            <span className="text-foreground">„{f.ack.reason}“</span>
            <span className="block text-muted-foreground">
              {f.ack.by} · {fmtDate(f.ack.at)}
              {f.ack.expires_at && ` · gültig bis ${fmtDate(f.ack.expires_at)}`}
            </span>
          </span>
        )}
        {f.ack_stale && (
          <span className="mt-1 flex items-center gap-1.5 text-xs text-warning">
            <TriangleAlert className="size-3.5" /> Frühere Akzeptanz ungültig: {f.ack_stale.why} („{f.ack_stale.reason}“)
          </span>
        )}
      </span>
      {onAck && (
        <Button size="sm" variant="outline" onClick={onAck}>
          <BadgeCheck /> Als okay markieren
        </Button>
      )}
      {onRevoke && (
        <Button size="sm" variant="ghost" onClick={onRevoke}>
          <Undo2 /> Zurücknehmen
        </Button>
      )}
    </li>
  );
}

export function AuditTab({ fwId }: { fwId: number }) {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const qc = useQueryClient();
  const [days, setDays] = useState(30);
  const [kind, setKind] = useState<FindingKind | null>(null);
  const [acking, setAcking] = useState<AuditFinding | null>(null);
  const q = useQuery({
    queryKey: ["audit", fwId, days],
    queryFn: () => api<AuditResult>(`/api/firewalls/${fwId}/audit`, { params: { unused_days: days } }),
  });
  const revoke = useMutation({
    mutationFn: (ackId: number) => api(`/api/firewalls/${fwId}/audit/acks/${ackId}`, { method: "DELETE" }),
    onSuccess: () => {
      toast("Akzeptanz zurückgenommen");
      qc.invalidateQueries({ queryKey: ["audit", fwId] });
    },
  });

  if (q.isPending) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const a = q.data;
  const filtered = kind ? a.findings.filter((f) => f.kind === kind) : a.findings;
  const open = filtered.filter((f) => !f.ack);
  const accepted = filtered.filter((f) => f.ack);
  const enoughData = a.data_since && Date.now() - new Date(a.data_since).getTime() >= days * 86400_000;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-muted-foreground">
          {a.rule_count} Regeln, davon {a.enabled_count} aktiv · Nutzungsdaten seit {fmtDate(a.data_since)}
          {a.acknowledged > 0 && ` · ${a.acknowledged} akzeptiert`}
        </p>
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          Ungenutzt seit
          <Select value={String(days)} onValueChange={(v) => setDays(Number(v))}>
            <SelectTrigger size="sm" className="w-32"><SelectValue /></SelectTrigger>
            <SelectContent>
              {[7, 30, 60, 90, 180, 365].map((d) => <SelectItem key={d} value={String(d)}>{d} Tagen</SelectItem>)}
            </SelectContent>
          </Select>
        </div>
      </div>
      {!enoughData && (
        <Alert className="border-warning/40 bg-warning/5">
          <TriangleAlert className="text-warning" />
          <AlertDescription>
            Für „ungenutzt seit {days} Tagen“ reichen die gesammelten Logs noch nicht – diese Prüfung startet, sobald genug Daten da sind.
          </AlertDescription>
        </Alert>
      )}

      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        {KINDS.map((k) => {
          const Icon = KIND_ICON[k];
          const count = a.summary[k] ?? 0;
          return (
            <button
              key={k}
              onClick={() => setKind(kind === k ? null : k)}
              aria-pressed={kind === k}
              title={KIND_HINT[k]}
              className={cn(
                "rounded-xl border bg-card p-4 text-left transition-all hover:border-primary/40",
                kind === k && "border-primary shadow-glow",
              )}
            >
              <div className="flex items-center justify-between text-xs font-medium text-muted-foreground">
                {KIND_LABEL[k]}
                <Icon className={cn("size-4", count ? "text-primary" : "opacity-50")} />
              </div>
              <div className="mt-1 text-2xl font-semibold tabular-nums">{count}</div>
            </button>
          );
        })}
      </div>
      {kind && <p className="text-sm text-muted-foreground">{KIND_HINT[kind]}</p>}

      {open.length === 0 ? (
        <Empty>{kind ? "Keine offenen Befunde in dieser Kategorie" : "Keine offenen Befunde – das Regelwerk sieht sauber aus"}</Empty>
      ) : (
        <Card className="py-0">
          <ul>
            {open.map((f, i) => (
              <FindingRow key={`${f.kind}-${f.rule}-${i}`} f={f} onAck={isAdmin ? () => setAcking(f) : undefined} />
            ))}
          </ul>
        </Card>
      )}

      {accepted.length > 0 && (
        <Collapsible>
          <CollapsibleTrigger asChild>
            <Button variant="ghost" className="group gap-2 px-2">
              <BadgeCheck className="text-good" /> Akzeptierte Befunde ({accepted.length})
              <ChevronDown className="transition-transform group-data-[state=open]:rotate-180" />
            </Button>
          </CollapsibleTrigger>
          <CollapsibleContent>
            <Card className="mt-2 py-0">
              <ul>
                {accepted.map((f, i) => (
                  <FindingRow
                    key={`${f.kind}-${f.rule}-${i}`}
                    f={f}
                    onRevoke={isAdmin ? () => revoke.mutate(f.ack!.id) : undefined}
                  />
                ))}
              </ul>
            </Card>
          </CollapsibleContent>
        </Collapsible>
      )}

      <p className="text-xs text-muted-foreground">
        „Verdeckt“ und „Redundant“ vergleichen Zonen, Netze, Dienste, Identitäten und Zeitplan über die Objektnamen.
        Gruppeninhalte und überlappende IP-Bereiche werden nicht aufgelöst – es werden nur eindeutige Fälle gemeldet.
        {!isAdmin && " Befunde akzeptieren können nur Administratoren."}
      </p>
      <AckDialog fwId={fwId} finding={acking} onClose={() => setAcking(null)} />
    </div>
  );
}
