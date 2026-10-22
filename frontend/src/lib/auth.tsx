import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createContext, useContext, useEffect, type ReactNode } from "react";
import { api, ApiError } from "./api";
import type { User } from "./types";

interface AuthState {
  user: User | null;
  loading: boolean;
  setUser: (u: User | null) => void;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const me = useQuery({
    queryKey: ["me"],
    queryFn: async () => {
      try {
        return await api<User | null>("/api/auth/me");
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) return null;
        throw e;
      }
    },
    staleTime: 60_000,
    retry: false,
  });

  // Beim Abmelden nur die Daten verwerfen, nicht den "me"-Eintrag: qc.clear() würde ihn entfernen, der
  // Beobachter dieser Komponente hinge dann an einem verwaisten Eintrag und bekäme den nächsten Login nicht mit.
  const signedOut = () => {
    qc.removeQueries({ predicate: (q) => q.queryKey[0] !== "me" });
    qc.setQueryData(["me"], null);
  };

  useEffect(() => {
    window.addEventListener("auth:expired", signedOut);
    return () => window.removeEventListener("auth:expired", signedOut);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [qc]);

  const value: AuthState = {
    user: me.data ?? null,
    loading: me.isPending,
    setUser: (u) => {
      if (u) qc.removeQueries({ predicate: (q) => q.queryKey[0] !== "me" });
      qc.setQueryData(["me"], u);
    },
    logout: async () => {
      try {
        await api("/api/auth/logout", { method: "POST" });
      } finally {
        signedOut();
      }
    },
  };
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth außerhalb von AuthProvider");
  return ctx;
}
