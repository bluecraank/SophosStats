import { useState, type FormEvent } from "react";
import { Navigate } from "react-router";
import { ErrorBox, Field } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { useAuth } from "../lib/auth";
import type { User } from "../lib/types";

export function LoginPage() {
  const { user, setUser } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [needTotp, setNeedTotp] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (user) return <Navigate to="/" replace />;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const u = await api<User>("/api/auth/login", {
        method: "POST",
        body: { username, password, totp_code: needTotp ? totp : null },
      });
      setUser(u);
    } catch (err) {
      if (err instanceof ApiError && err.message === "totp_required") {
        setNeedTotp(true);
      } else {
        setError(err instanceof Error ? err.message : "Anmeldung fehlgeschlagen");
        if (needTotp) setTotp("");
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <form onSubmit={submit} className="w-full max-w-sm space-y-4 rounded-lg border border-line bg-surface p-6">
        <div className="flex items-center gap-2">
          <img src="/favicon.svg" alt="" className="size-7" />
          <h1 className="text-lg font-semibold">SophosStats</h1>
        </div>
        <ErrorBox error={error} />
        {!needTotp ? (
          <>
            <Field label="Benutzername">
              <input className="input" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required autoFocus />
            </Field>
            <Field label="Passwort">
              <input className="input" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
            </Field>
          </>
        ) : (
          <Field label="Code aus der Authenticator-App">
            <input
              className="input tracking-widest"
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]{6,8}"
              value={totp}
              onChange={(e) => setTotp(e.target.value.replace(/\D/g, ""))}
              required
              autoFocus
            />
          </Field>
        )}
        <button className="btn-primary w-full" disabled={busy}>
          {busy ? "Anmelden …" : needTotp ? "Bestätigen" : "Anmelden"}
        </button>
        {needTotp && (
          <button type="button" className="w-full cursor-pointer text-xs text-ink-2 hover:underline" onClick={() => { setNeedTotp(false); setTotp(""); }}>
            Zurück
          </button>
        )}
      </form>
    </div>
  );
}
