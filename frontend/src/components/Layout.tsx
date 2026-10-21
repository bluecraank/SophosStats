import { useQuery } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";
import { Navigate, NavLink, Outlet } from "react-router";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import type { Firewall } from "../lib/types";

function NavItem({ to, children, onClick }: { to: string; children: ReactNode; onClick?: () => void }) {
  return (
    <NavLink
      to={to}
      end={to === "/"}
      onClick={onClick}
      className={({ isActive }) =>
        `block truncate rounded-md px-3 py-1.5 text-sm ${
          isActive ? "bg-accent/12 font-medium text-ink" : "text-ink-2 hover:bg-surface-2 hover:text-ink"
        }`
      }
    >
      {children}
    </NavLink>
  );
}

export function Layout() {
  const { user, loading, logout } = useAuth();
  const [open, setOpen] = useState(false);
  const firewalls = useQuery({
    queryKey: ["firewalls"],
    queryFn: () => api<Firewall[]>("/api/firewalls"),
    enabled: !!user,
  });

  if (loading) return null;
  if (!user) return <Navigate to="/login" replace />;
  const close = () => setOpen(false);

  return (
    <div className="min-h-screen md:flex">
      <header className="flex items-center justify-between border-b border-line bg-surface px-4 py-3 md:hidden">
        <span className="font-semibold">SophosStats</span>
        <button className="btn-secondary" onClick={() => setOpen(!open)} aria-expanded={open}>
          Menü
        </button>
      </header>
      <aside
        className={`${open ? "block" : "hidden"} border-r border-line bg-surface md:sticky md:top-0 md:block md:h-screen md:w-60 md:shrink-0`}
      >
        <div className="flex h-full flex-col gap-6 overflow-y-auto p-4">
          <div className="hidden items-center gap-2 md:flex">
            <img src="/favicon.svg" alt="" className="size-6" />
            <span className="font-semibold">SophosStats</span>
          </div>
          <nav className="space-y-0.5">
            <NavItem to="/" onClick={close}>Übersicht</NavItem>
            <NavItem to="/logs" onClick={close}>Logs</NavItem>
          </nav>
          <div>
            <div className="mb-1 px-3 text-xs font-medium uppercase tracking-wide text-muted">Firewalls</div>
            <nav className="space-y-0.5">
              {firewalls.data?.map((fw) => (
                <NavItem key={fw.id} to={`/firewalls/${fw.id}`} onClick={close}>
                  {fw.name}
                </NavItem>
              ))}
              {firewalls.data?.length === 0 && <div className="px-3 text-xs text-muted">Noch keine angelegt</div>}
            </nav>
          </div>
          {user.role === "admin" && (
            <div>
              <div className="mb-1 px-3 text-xs font-medium uppercase tracking-wide text-muted">Verwaltung</div>
              <nav className="space-y-0.5">
                <NavItem to="/admin/firewalls" onClick={close}>Firewalls verwalten</NavItem>
                <NavItem to="/admin/users" onClick={close}>Benutzer</NavItem>
              </nav>
            </div>
          )}
          <div className="mt-auto space-y-0.5 border-t border-line pt-4">
            <NavItem to="/account" onClick={close}>
              {user.username} <span className="text-muted">({user.role})</span>
            </NavItem>
            <button
              onClick={logout}
              className="block w-full cursor-pointer rounded-md px-3 py-1.5 text-left text-sm text-ink-2 hover:bg-surface-2"
            >
              Abmelden
            </button>
          </div>
        </div>
      </aside>
      <main className="min-w-0 flex-1 p-4 md:p-6">
        <Outlet />
      </main>
    </div>
  );
}
