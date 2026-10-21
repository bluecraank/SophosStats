import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type ChangeEvent, type FormEvent } from "react";
import { Card, Empty, ErrorBox, Field, Loading, StatusBadge } from "../components/ui";
import { api } from "../lib/api";
import type { Firewall } from "../lib/types";
import { SourceBadges } from "./DashboardPage";

interface TestResult {
  xml_api_ok: boolean;
  xml_api_message: string;
  snmp_ok: boolean | null;
  snmp_message: string;
}

type FormState = Record<string, string | number | boolean>;

const DEFAULTS: FormState = {
  name: "",
  host: "",
  enabled: true,
  api_port: 4444,
  api_username: "",
  api_password: "",
  verify_tls: false,
  snmp_enabled: true,
  snmp_port: 161,
  snmp_username: "",
  snmp_auth_protocol: "SHA256",
  snmp_auth_key: "",
  snmp_priv_protocol: "AES128",
  snmp_priv_key: "",
  syslog_source_ip: "",
  metrics_interval_s: 60,
  config_interval_s: 900,
};

function toForm(fw: Firewall): FormState {
  const f: FormState = { ...DEFAULTS };
  for (const key of Object.keys(DEFAULTS)) {
    const v = (fw as unknown as Record<string, unknown>)[key];
    if (v !== undefined && v !== null) f[key] = v as string | number | boolean;
  }
  f.api_password = f.snmp_auth_key = f.snmp_priv_key = "";
  return f;
}

function FirewallForm({ initial, onDone }: { initial: Firewall | null; onDone: () => void }) {
  const qc = useQueryClient();
  const [f, setF] = useState<FormState>(initial ? toForm(initial) : DEFAULTS);
  const set = (k: string) => (e: ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
    setF({ ...f, [k]: e.target.type === "checkbox" ? (e.target as HTMLInputElement).checked : e.target.type === "number" ? Number(e.target.value) : e.target.value });

  const save = useMutation({
    mutationFn: () => {
      const body: Record<string, unknown> = { ...f };
      for (const k of ["snmp_username", "syslog_source_ip"]) if (body[k] === "") body[k] = null;
      // Leere Secrets: beim Anlegen weglassen, beim Bearbeiten = unverändert
      for (const k of ["api_password", "snmp_auth_key", "snmp_priv_key"]) if (body[k] === "") delete body[k];
      return initial
        ? api(`/api/firewalls/${initial.id}`, { method: "PATCH", body })
        : api("/api/firewalls", { method: "POST", body });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["firewalls"] });
      qc.invalidateQueries({ queryKey: ["dashboard"] });
      onDone();
    },
  });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    save.mutate();
  };
  const secretHint = initial ? "Leer lassen = unverändert" : undefined;

  return (
    <form onSubmit={submit} className="space-y-6">
      <ErrorBox error={save.error} />
      <fieldset className="grid gap-4 md:grid-cols-3">
        <legend className="mb-2 text-sm font-semibold">Allgemein</legend>
        <Field label="Name"><input className="input" value={String(f.name)} onChange={set("name")} required /></Field>
        <Field label="Host / IP"><input className="input" value={String(f.host)} onChange={set("host")} required /></Field>
        <label className="flex items-center gap-2 self-end pb-2 text-sm">
          <input type="checkbox" checked={Boolean(f.enabled)} onChange={set("enabled")} /> Abruf aktiv
        </label>
      </fieldset>

      <fieldset className="grid gap-4 md:grid-cols-3">
        <legend className="mb-2 text-sm font-semibold">XML-API (Regeln & Konfiguration)</legend>
        <Field label="API-Benutzer"><input className="input" value={String(f.api_username)} onChange={set("api_username")} required autoComplete="off" /></Field>
        <Field label="API-Passwort" hint={secretHint}>
          <input className="input" type="password" value={String(f.api_password)} onChange={set("api_password")} required={!initial} autoComplete="new-password" />
        </Field>
        <Field label="Port"><input className="input" type="number" value={Number(f.api_port)} onChange={set("api_port")} /></Field>
        <label className="flex items-center gap-2 text-sm md:col-span-3">
          <input type="checkbox" checked={Boolean(f.verify_tls)} onChange={set("verify_tls")} />
          TLS-Zertifikat prüfen (empfohlen, wenn die Firewall ein vertrauenswürdiges Zertifikat hat)
        </label>
        <Field label="Konfig-Intervall (Sekunden)"><input className="input" type="number" min={60} value={Number(f.config_interval_s)} onChange={set("config_interval_s")} /></Field>
      </fieldset>

      <fieldset className="grid gap-4 md:grid-cols-3">
        <legend className="mb-2 text-sm font-semibold">SNMP v3 (CPU, RAM, Disk, Interfaces)</legend>
        <label className="flex items-center gap-2 text-sm md:col-span-3">
          <input type="checkbox" checked={Boolean(f.snmp_enabled)} onChange={set("snmp_enabled")} /> SNMP abfragen
        </label>
        {f.snmp_enabled && (
          <>
            <Field label="SNMP-Benutzer"><input className="input" value={String(f.snmp_username)} onChange={set("snmp_username")} required autoComplete="off" /></Field>
            <Field label="Auth-Protokoll">
              <select className="input" value={String(f.snmp_auth_protocol)} onChange={set("snmp_auth_protocol")}>
                {["SHA", "SHA224", "SHA256", "SHA384", "SHA512", "MD5"].map((p) => <option key={p}>{p}</option>)}
              </select>
            </Field>
            <Field label="Auth-Passwort" hint={secretHint ?? "min. 8 Zeichen"}>
              <input className="input" type="password" value={String(f.snmp_auth_key)} onChange={set("snmp_auth_key")} autoComplete="new-password" />
            </Field>
            <Field label="Port"><input className="input" type="number" value={Number(f.snmp_port)} onChange={set("snmp_port")} /></Field>
            <Field label="Verschlüsselung">
              <select className="input" value={String(f.snmp_priv_protocol)} onChange={set("snmp_priv_protocol")}>
                {["AES128", "AES192", "AES256", "DES", "3DES", "NONE"].map((p) => <option key={p}>{p}</option>)}
              </select>
            </Field>
            <Field label="Verschlüsselungs-Passwort" hint={secretHint ?? "min. 8 Zeichen"}>
              <input className="input" type="password" value={String(f.snmp_priv_key)} onChange={set("snmp_priv_key")} autoComplete="new-password" />
            </Field>
            <Field label="Metrik-Intervall (Sekunden)"><input className="input" type="number" min={15} value={Number(f.metrics_interval_s)} onChange={set("metrics_interval_s")} /></Field>
          </>
        )}
      </fieldset>

      <fieldset className="grid gap-4 md:grid-cols-3">
        <legend className="mb-2 text-sm font-semibold">Syslog (Logs & Regelnutzung)</legend>
        <Field label="Absender-IP der Logs" hint="Nur nötig, wenn die Firewall Syslog von einer anderen IP als dem Host sendet">
          <input className="input" value={String(f.syslog_source_ip)} onChange={set("syslog_source_ip")} />
        </Field>
      </fieldset>

      <div className="flex gap-2">
        <button className="btn-primary" disabled={save.isPending}>{save.isPending ? "Speichern …" : "Speichern"}</button>
        <button type="button" className="btn-secondary" onClick={onDone}>Abbrechen</button>
      </div>
    </form>
  );
}

function FirewallRow({ fw, onEdit }: { fw: Firewall; onEdit: () => void }) {
  const qc = useQueryClient();
  const test = useMutation({ mutationFn: () => api<TestResult>(`/api/firewalls/${fw.id}/test`, { method: "POST" }) });
  const remove = useMutation({
    mutationFn: () => api(`/api/firewalls/${fw.id}`, { method: "DELETE" }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["firewalls"] });
      qc.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });

  return (
    <div className="space-y-3 border-t border-line py-4 first:border-t-0 first:pt-0">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <div className="font-medium">{fw.name} {!fw.enabled && <span className="text-xs text-muted">(deaktiviert)</span>}</div>
          <div className="text-xs text-ink-2">{fw.host}:{fw.api_port} · {fw.model ?? "?"} · {fw.firmware ?? "?"}</div>
        </div>
        <div className="flex flex-wrap gap-2">
          <button className="btn-secondary" onClick={() => test.mutate()} disabled={test.isPending}>{test.isPending ? "Teste …" : "Verbindung testen"}</button>
          <button className="btn-secondary" onClick={onEdit}>Bearbeiten</button>
          <button
            className="btn-danger"
            onClick={() => confirm(`Firewall „${fw.name}“ samt aller gesammelten Daten löschen?`) && remove.mutate()}
          >
            Löschen
          </button>
        </div>
      </div>
      <SourceBadges fw={fw} />
      <ErrorBox error={test.error ?? remove.error} />
      {test.data && (
        <div className="space-y-1 rounded-md bg-surface-2 px-3 py-2 text-sm">
          <div><StatusBadge status={test.data.xml_api_ok ? "good" : "critical"} label="XML-API" /> <span className="ml-2">{test.data.xml_api_message}</span></div>
          <div>
            <StatusBadge status={test.data.snmp_ok == null ? "off" : test.data.snmp_ok ? "good" : "critical"} label="SNMP" />{" "}
            <span className="ml-2">{test.data.snmp_message}</span>
          </div>
        </div>
      )}
    </div>
  );
}

export function AdminFirewallsPage() {
  const [editing, setEditing] = useState<Firewall | "new" | null>(null);
  const q = useQuery({ queryKey: ["firewalls"], queryFn: () => api<Firewall[]>("/api/firewalls") });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Firewalls verwalten</h1>
        {!editing && <button className="btn-primary" onClick={() => setEditing("new")}>Firewall hinzufügen</button>}
      </div>
      {editing && (
        <Card title={editing === "new" ? "Neue Firewall" : `${editing.name} bearbeiten`}>
          <FirewallForm key={editing === "new" ? "new" : editing.id} initial={editing === "new" ? null : editing} onDone={() => setEditing(null)} />
        </Card>
      )}
      <Card>
        <ErrorBox error={q.error} />
        {q.isPending ? <Loading /> : q.data?.length === 0 ? <Empty>Noch keine Firewall angelegt</Empty> : q.data?.map((fw) => (
          <FirewallRow key={fw.id} fw={fw} onEdit={() => setEditing(fw)} />
        ))}
      </Card>
      <Card title="Einrichtung auf der Sophos-Firewall">
        <ol className="list-decimal space-y-2 pl-5 text-sm text-ink-2">
          <li><strong className="text-ink">XML-API:</strong> Backup &amp; firmware → API → „API configuration“ aktivieren und die IP dieses Servers als „Allowed IP address“ eintragen. Einen eigenen Admin mit Leserechten verwenden.</li>
          <li><strong className="text-ink">SNMP v3:</strong> Administration → SNMP → SNMP-Agent aktivieren, SNMPv3-Benutzer anlegen (Auth SHA256, Verschlüsselung AES). Unter Administration → Device access SNMP für die Zone dieses Servers erlauben.</li>
          <li><strong className="text-ink">Syslog:</strong> System services → Log settings → Syslog-Server hinzufügen: IP dieses Servers, Port 5514 (UDP oder TCP), Format „Device standard format“. Mindestens die Kategorie „Firewall“ aktivieren.</li>
          <li><strong className="text-ink">Regelnutzung:</strong> In jeder Firewall-Regel „Log firewall traffic“ einschalten – nur geloggte Regeln liefern Treffer und Bytes.</li>
        </ol>
      </Card>
    </div>
  );
}
