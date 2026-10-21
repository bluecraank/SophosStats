import { KeyRound, Loader2, Shield } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Navigate } from "react-router";
import { ErrorBox } from "@/components/ui";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { User } from "@/lib/types";

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
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden p-4">
      {/* Leuchtender Hintergrund */}
      <div className="pointer-events-none absolute -top-40 left-1/2 size-[36rem] -translate-x-1/2 rounded-full bg-primary/15 blur-3xl" />
      <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(to_right,var(--grid)_1px,transparent_1px),linear-gradient(to_bottom,var(--grid)_1px,transparent_1px)] bg-[size:48px_48px] [mask-image:radial-gradient(ellipse_at_center,black_30%,transparent_75%)]" />

      <Card className="relative w-full max-w-sm border-primary/20 bg-card/80 shadow-2xl backdrop-blur-xl">
        <CardHeader className="items-center text-center">
          <div className="mx-auto mb-2 flex size-12 items-center justify-center rounded-xl bg-primary text-primary-foreground shadow-glow">
            {needTotp ? <KeyRound className="size-6" /> : <Shield className="size-6" />}
          </div>
          <CardTitle className="text-xl">{needTotp ? "Zwei-Faktor-Bestätigung" : "SophosStats"}</CardTitle>
          <CardDescription>
            {needTotp ? "Code aus deiner Authenticator-App eingeben" : "Anmelden, um fortzufahren"}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={submit} className="space-y-4">
            <ErrorBox error={error} />
            {!needTotp ? (
              <>
                <div className="space-y-2">
                  <Label htmlFor="username">Benutzername</Label>
                  <Input id="username" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required autoFocus />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="password">Passwort</Label>
                  <Input id="password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
                </div>
              </>
            ) : (
              <Input
                aria-label="Einmalcode"
                className="h-12 text-center font-mono text-2xl tracking-[0.5em]"
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="[0-9]{6,8}"
                maxLength={8}
                placeholder="000000"
                value={totp}
                onChange={(e) => setTotp(e.target.value.replace(/\D/g, ""))}
                required
                autoFocus
              />
            )}
            <Button className="w-full shadow-glow" disabled={busy}>
              {busy && <Loader2 className="animate-spin" />}
              {busy ? "Anmelden …" : needTotp ? "Bestätigen" : "Anmelden"}
            </Button>
            {needTotp && (
              <Button type="button" variant="ghost" className="w-full" onClick={() => { setNeedTotp(false); setTotp(""); }}>
                Zurück
              </Button>
            )}
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
