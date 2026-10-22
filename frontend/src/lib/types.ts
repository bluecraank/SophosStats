export type Role = "admin" | "viewer";

export interface User {
  id: number;
  username: string;
  role: Role;
  is_active: boolean;
  totp_enabled: boolean;
  last_login: string | null;
  created_at: string;
}

export interface Firewall {
  id: number;
  name: string;
  host: string;
  enabled: boolean;
  api_port: number;
  api_username: string;
  verify_tls: boolean;
  snmp_enabled: boolean;
  snmp_port: number;
  snmp_username: string | null;
  snmp_auth_protocol: string;
  snmp_priv_protocol: string;
  syslog_source_ip: string | null;
  site_networks: string | null;
  site_link_zone: string | null;
  metrics_interval_s: number;
  config_interval_s: number;
  model: string | null;
  firmware: string | null;
  serial: string | null;
  api_version: string | null;
  last_metrics_at: string | null;
  last_metrics_error: string | null;
  last_config_at: string | null;
  last_config_error: string | null;
  last_config_warning: string | null;
  last_log_at: string | null;
  created_at: string;
}

export interface DashboardEntry {
  firewall: Firewall;
  metrics: Record<string, number>;
  hits_24h: number;
  denied_24h: number;
  bytes_24h: number;
}

export interface MetricPoint {
  t: string;
  v: number;
  max: number;
}

export interface Usage {
  rule_id: number;
  hits: number;
  denied: number;
  sent_bytes: number;
  recv_bytes: number;
  sent_pkts: number;
  recv_pkts: number;
  last_seen: string | null;
}

export interface Rule {
  name: string;
  description: string | null;
  enabled: boolean;
  policy_type: string | null;
  ip_family: string | null;
  action: string | null;
  log_traffic: boolean;
  schedule: string | null;
  source_zones: string[];
  destination_zones: string[];
  source_networks: string[];
  destination_networks: string[];
  services: string[];
  identities: string[];
  position: number;
  group: string | null;
  rule_id: number | null;
  usage: Usage | null;
  last_seen_ever: string | null;
}

export interface RulesResponse {
  hours: number;
  data_since: string | null;
  rules: Rule[];
  unmapped_usage: (Usage & { rule_name: string | null })[];
}

export interface LogItem {
  id: number;
  time: string;
  firewall_id: number | null;
  log_type: string | null;
  log_component: string | null;
  log_subtype: string | null;
  status: string | null;
  severity: string | null;
  rule_id: number | null;
  rule_name: string | null;
  src_ip: string | null;
  src_port: number | null;
  dst_ip: string | null;
  dst_port: number | null;
  protocol: string | null;
  user_name: string | null;
  sent_bytes: number | null;
  recv_bytes: number | null;
  message: string | null;
  fields: Record<string, string>;
}

export interface ChangeActor {
  time: string;
  user: string | null;
  src_ip: string | null;
  via: string | null;
  message: string;
  /** true = Objektname steht in der Admin-Meldung; false = nur zeitlich passende Admin-Aktion */
  exact: boolean;
}

export interface ConfigChange {
  id: number;
  time: string;
  window_start: string | null;
  entity_type: string;
  name: string;
  action: "added" | "removed" | "modified";
  old: unknown;
  new: unknown;
  actors: ChangeActor[];
}

export type FindingKind = "shadowed" | "redundant" | "too_broad" | "unused" | "no_logging" | "disabled";

export interface AuditFinding {
  kind: FindingKind;
  severity: "high" | "medium" | "low" | "info";
  rule: string;
  rule_id: number | null;
  position: number | null;
  message: string;
  covered_by?: string;
  last_seen?: string;
  open_dimensions?: string[];
  ack?: FindingAck;
  ack_stale?: FindingAck & { why: string };
}

export interface FindingAck {
  id: number;
  reason: string;
  by: string;
  at: string;
  expires_at: string | null;
}

export interface AuditResult {
  unused_days: number;
  data_since: string | null;
  rule_count: number;
  enabled_count: number;
  summary: Partial<Record<FindingKind, number>>;
  acknowledged: number;
  findings: AuditFinding[];
}

export interface TopEntry {
  key: string;
  hits: number;
  sent_bytes: number;
  recv_bytes: number;
}
