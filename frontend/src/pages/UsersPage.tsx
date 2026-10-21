import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Card, ErrorBox, Field, Loading, Pill } from "../components/ui";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { fmtRelative } from "../lib/format";
import type { Role, User } from "../lib/types";

export function UsersPage() {
  const { user: me } = useAuth();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["users"], queryFn: () => api<User[]>("/api/users") });
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("viewer");

  const refresh = () => qc.invalidateQueries({ queryKey: ["users"] });
  const create = useMutation({
    mutationFn: () => api("/api/users", { method: "POST", body: { username, password, role } }),
    onSuccess: () => {
      setUsername("");
      setPassword("");
      refresh();
    },
  });
  const update = useMutation({
    mutationFn: ({ id, body }: { id: number; body: Record<string, unknown> }) => api(`/api/users/${id}`, { method: "PATCH", body }),
    onSuccess: refresh,
  });
  const remove = useMutation({
    mutationFn: (id: number) => api(`/api/users/${id}`, { method: "DELETE" }),
    onSuccess: refresh,
  });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    create.mutate();
  };

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Benutzer</h1>
      <Card title="Neuer Benutzer">
        <form onSubmit={submit} className="grid items-end gap-3 md:grid-cols-[1fr_1fr_10rem_auto]">
          <Field label="Benutzername"><input className="input" value={username} onChange={(e) => setUsername(e.target.value)} required autoComplete="off" /></Field>
          <Field label="Passwort (min. 12 Zeichen)">
            <input className="input" type="password" minLength={12} value={password} onChange={(e) => setPassword(e.target.value)} required autoComplete="new-password" />
          </Field>
          <Field label="Rolle">
            <select className="input" value={role} onChange={(e) => setRole(e.target.value as Role)}>
              <option value="viewer">Betrachter</option>
              <option value="admin">Administrator</option>
            </select>
          </Field>
          <button className="btn-primary" disabled={create.isPending}>Anlegen</button>
        </form>
        <div className="mt-3"><ErrorBox error={create.error} /></div>
      </Card>

      <Card>
        <ErrorBox error={q.error ?? update.error ?? remove.error} />
        {q.isPending ? <Loading /> : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-xs text-muted-foreground">
                <tr>
                  <th className="py-2 font-medium">Benutzer</th>
                  <th className="py-2 font-medium">Rolle</th>
                  <th className="py-2 font-medium">2FA</th>
                  <th className="py-2 font-medium">Letzter Login</th>
                  <th className="py-2 font-medium" />
                </tr>
              </thead>
              <tbody>
                {q.data?.map((u) => (
                  <tr key={u.id} className="border-t border-border">
                    <td className="py-2">
                      {u.username} {!u.is_active && <Pill>deaktiviert</Pill>} {u.id === me?.id && <Pill tone="accent">du</Pill>}
                    </td>
                    <td className="py-2">
                      <select
                        className="input w-auto py-1"
                        value={u.role}
                        disabled={u.id === me?.id}
                        onChange={(e) => update.mutate({ id: u.id, body: { role: e.target.value } })}
                        aria-label={`Rolle von ${u.username}`}
                      >
                        <option value="viewer">Betrachter</option>
                        <option value="admin">Administrator</option>
                      </select>
                    </td>
                    <td className="py-2">{u.totp_enabled ? <Pill tone="good">aktiv</Pill> : <Pill>aus</Pill>}</td>
                    <td className="py-2 text-muted-foreground">{fmtRelative(u.last_login)}</td>
                    <td className="py-2">
                      {u.id !== me?.id && (
                        <div className="flex flex-wrap justify-end gap-2">
                          <button
                            className="btn-secondary py-1"
                            onClick={() => {
                              const pw = prompt(`Neues Passwort für ${u.username} (min. 12 Zeichen)`);
                              if (pw) update.mutate({ id: u.id, body: { password: pw } });
                            }}
                          >
                            Passwort
                          </button>
                          {u.totp_enabled && (
                            <button className="btn-secondary py-1" onClick={() => confirm(`2FA für ${u.username} zurücksetzen?`) && update.mutate({ id: u.id, body: { reset_totp: true } })}>
                              2FA zurücksetzen
                            </button>
                          )}
                          <button className="btn-secondary py-1" onClick={() => update.mutate({ id: u.id, body: { is_active: !u.is_active } })}>
                            {u.is_active ? "Deaktivieren" : "Aktivieren"}
                          </button>
                          <button className="btn-danger py-1" onClick={() => confirm(`${u.username} löschen?`) && remove.mutate(u.id)}>
                            Löschen
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
