import { useMutation } from "@tanstack/react-query";
import { QRCodeSVG } from "qrcode.react";
import { useState, type FormEvent } from "react";
import { Card, ErrorBox, Field } from "../components/ui";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import type { User } from "../lib/types";

function PasswordCard() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [repeat, setRepeat] = useState("");
  const change = useMutation({
    mutationFn: () => api("/api/auth/password", { method: "POST", body: { current_password: current, new_password: next } }),
    onSuccess: () => {
      setCurrent("");
      setNext("");
      setRepeat("");
    },
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (next === repeat) change.mutate();
  };
  return (
    <Card title="Passwort ändern">
      <form onSubmit={submit} className="max-w-sm space-y-3">
        <ErrorBox error={change.error} />
        {change.isSuccess && <div className="text-sm text-ink-2">Passwort geändert. Andere Sitzungen wurden abgemeldet.</div>}
        <Field label="Aktuelles Passwort"><input className="input" type="password" value={current} onChange={(e) => setCurrent(e.target.value)} required autoComplete="current-password" /></Field>
        <Field label="Neues Passwort (min. 12 Zeichen)"><input className="input" type="password" minLength={12} value={next} onChange={(e) => setNext(e.target.value)} required autoComplete="new-password" /></Field>
        <Field label="Wiederholen"><input className="input" type="password" value={repeat} onChange={(e) => setRepeat(e.target.value)} required autoComplete="new-password" /></Field>
        {repeat && next !== repeat && <div className="text-xs text-critical">Passwörter stimmen nicht überein</div>}
        <button className="btn-primary" disabled={change.isPending}>Ändern</button>
      </form>
    </Card>
  );
}

function TotpCard() {
  const { user, setUser } = useAuth();
  const [setup, setSetup] = useState<{ secret: string; uri: string } | null>(null);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");

  const start = useMutation({
    mutationFn: () => api<{ secret: string; uri: string }>("/api/auth/totp/setup", { method: "POST" }),
    onSuccess: setSetup,
  });
  const enable = useMutation({
    mutationFn: () => api<User>("/api/auth/totp/enable", { method: "POST", body: { code } }),
    onSuccess: (u) => {
      setUser(u);
      setSetup(null);
      setCode("");
    },
  });
  const disable = useMutation({
    mutationFn: () => api<User>("/api/auth/totp/disable", { method: "POST", body: { password } }),
    onSuccess: (u) => {
      setUser(u);
      setPassword("");
    },
  });

  return (
    <Card title="Zwei-Faktor-Authentifizierung (TOTP)">
      <ErrorBox error={start.error ?? enable.error ?? disable.error} />
      {user?.totp_enabled ? (
        <form className="max-w-sm space-y-3" onSubmit={(e) => { e.preventDefault(); disable.mutate(); }}>
          <p className="text-sm">2FA ist <strong>aktiv</strong>.</p>
          <Field label="Passwort zum Deaktivieren"><input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required /></Field>
          <button className="btn-danger">2FA deaktivieren</button>
        </form>
      ) : setup ? (
        <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); enable.mutate(); }}>
          <p className="text-sm text-ink-2">QR-Code mit einer Authenticator-App scannen (z.B. Microsoft Authenticator, 2FAS, Aegis) und den angezeigten Code eingeben.</p>
          <div className="inline-block rounded-md bg-white p-3">
            <QRCodeSVG value={setup.uri} size={180} />
          </div>
          <p className="font-mono text-xs break-all text-ink-2">Manuell: {setup.secret}</p>
          <div className="flex max-w-sm gap-2">
            <input className="input tracking-widest" inputMode="numeric" autoComplete="one-time-code" placeholder="123456" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} required />
            <button className="btn-primary" disabled={enable.isPending}>Aktivieren</button>
          </div>
        </form>
      ) : (
        <div className="space-y-3">
          <p className="text-sm text-ink-2">Schützt dein Konto zusätzlich mit einem Einmalcode aus einer Authenticator-App.</p>
          <button className="btn-primary" onClick={() => start.mutate()} disabled={start.isPending}>2FA einrichten</button>
        </div>
      )}
    </Card>
  );
}

export function AccountPage() {
  const { user } = useAuth();
  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Konto: {user?.username}</h1>
      <TotpCard />
      <PasswordCard />
    </div>
  );
}
