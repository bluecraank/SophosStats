import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  GitCompareArrows,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Moon,
  Route,
  ScrollText,
  Search,
  Server,
  Settings2,
  Shield,
  Sun,
  Users,
} from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { Link, Navigate, Outlet, useLocation, useNavigate } from "react-router";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
import {
  Command,
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarRail,
  SidebarTrigger,
} from "@/components/ui/sidebar";
import { Separator } from "@/components/ui/separator";
import { Toaster } from "@/components/ui/sonner";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useTheme } from "@/lib/theme";
import type { Firewall } from "@/lib/types";
import { cn } from "@/lib/utils";
import { sourceStatus } from "@/pages/DashboardPage";

const STATUS_DOT = { good: "bg-good", warning: "bg-warning", critical: "bg-critical", off: "bg-muted-foreground/40" };

/** Schlechtester Status einer Firewall über alle Datenquellen – für den Punkt in der Navigation. */
function overallStatus(fw: Firewall) {
  const states = [
    sourceStatus(fw.last_metrics_at, fw.last_metrics_error, fw.metrics_interval_s, fw.snmp_enabled),
    sourceStatus(fw.last_config_at, fw.last_config_error, fw.config_interval_s),
  ];
  if (!fw.enabled) return "off";
  return states.includes("critical") ? "critical" : states.includes("warning") ? "warning" : "good";
}

function NavLinkItem({ to, icon: Icon, children, end }: { to: string; icon: typeof Activity; children: ReactNode; end?: boolean }) {
  const { pathname } = useLocation();
  const active = end ? pathname === to : pathname === to || pathname.startsWith(`${to}/`);
  return (
    <SidebarMenuItem>
      <SidebarMenuButton asChild isActive={active} tooltip={typeof children === "string" ? children : undefined}>
        <Link to={to}>
          <Icon />
          <span>{children}</span>
        </Link>
      </SidebarMenuButton>
    </SidebarMenuItem>
  );
}

function CommandMenu({ firewalls, isAdmin }: { firewalls: Firewall[]; isAdmin: boolean }) {
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key.toLowerCase() === "k" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  const go = (to: string) => {
    setOpen(false);
    navigate(to);
  };
  const tabs = [
    ["overview", "System"],
    ["rules", "Regeln"],
    ["audit", "Audit"],
    ["graph", "Beziehungen"],
    ["logs", "Logs"],
    ["changes", "Änderungen"],
  ];
  return (
    <>
      <Button
        variant="outline"
        size="sm"
        className="h-8 w-full max-w-64 justify-start gap-2 text-muted-foreground sm:w-64"
        onClick={() => setOpen(true)}
      >
        <Search className="size-4" />
        <span className="flex-1 text-left">Suchen …</span>
        <kbd className="pointer-events-none hidden rounded border bg-muted px-1.5 font-mono text-[10px] sm:inline">Strg K</kbd>
      </Button>
      <CommandDialog open={open} onOpenChange={setOpen} title="Suche" description="Seiten und Firewalls">
        {/* CommandDialog bringt keinen cmdk-Container mit – ohne <Command> stürzt die Liste ab */}
        <Command>
        <CommandInput placeholder="Firewall, Seite oder Bereich …" />
        <CommandList>
          <CommandEmpty>Nichts gefunden.</CommandEmpty>
          <CommandGroup heading="Seiten">
            <CommandItem onSelect={() => go("/")}><LayoutDashboard />Übersicht</CommandItem>
            <CommandItem onSelect={() => go("/logs")}><ScrollText />Logs</CommandItem>
            {firewalls.length > 1 && <CommandItem onSelect={() => go("/cross-site")}><Route />Standortübergreifend / Pfad verfolgen</CommandItem>}
            {firewalls.length > 1 && <CommandItem onSelect={() => go("/compare")}><GitCompareArrows />Firewalls vergleichen</CommandItem>}
            <CommandItem onSelect={() => go("/account")}><KeyRound />Konto &amp; 2FA</CommandItem>
            {isAdmin && <CommandItem onSelect={() => go("/admin/firewalls")}><Settings2 />Firewalls verwalten</CommandItem>}
            {isAdmin && <CommandItem onSelect={() => go("/admin/users")}><Users />Benutzer</CommandItem>}
          </CommandGroup>
          {firewalls.map((fw) => (
            <CommandGroup key={fw.id} heading={fw.name}>
              {tabs.map(([tab, label]) => (
                <CommandItem key={tab} value={`${fw.name} ${label}`} onSelect={() => go(`/firewalls/${fw.id}?tab=${tab}`)}>
                  <Server />
                  {fw.name} · {label}
                </CommandItem>
              ))}
            </CommandGroup>
          ))}
        </CommandList>
        </Command>
      </CommandDialog>
    </>
  );
}

export function Layout() {
  const { user, loading, logout } = useAuth();
  const { theme, setTheme } = useTheme();
  const location = useLocation();
  const firewalls = useQuery({
    queryKey: ["firewalls"],
    queryFn: () => api<Firewall[]>("/api/firewalls"),
    enabled: !!user,
    refetchInterval: 60_000,
  });

  if (loading) return null;
  if (!user) return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />;
  const fws = firewalls.data ?? [];
  const isAdmin = user.role === "admin";

  return (
    <SidebarProvider>
      <Sidebar collapsible="icon" variant="inset" className="print:hidden">
        <SidebarHeader>
          <SidebarMenu>
            <SidebarMenuItem>
              <SidebarMenuButton size="lg" asChild>
                <Link to="/">
                  <span className="flex size-8 items-center justify-center rounded-lg bg-primary text-primary-foreground shadow-glow">
                    <Shield className="size-4" />
                  </span>
                  <span className="grid leading-tight">
                    <span className="font-semibold">SophosStats</span>
                    <span className="text-xs text-muted-foreground">XGS Monitoring</span>
                  </span>
                </Link>
              </SidebarMenuButton>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarHeader>
        <SidebarContent>
          <SidebarGroup>
            <SidebarGroupLabel>Allgemein</SidebarGroupLabel>
            <SidebarMenu>
              <NavLinkItem to="/" icon={LayoutDashboard} end>Übersicht</NavLinkItem>
              <NavLinkItem to="/logs" icon={ScrollText}>Logs</NavLinkItem>
              {fws.length > 1 && <NavLinkItem to="/cross-site" icon={Route}>Standortübergreifend</NavLinkItem>}
              {fws.length > 1 && <NavLinkItem to="/compare" icon={GitCompareArrows}>Vergleichen</NavLinkItem>}
            </SidebarMenu>
          </SidebarGroup>
          <SidebarGroup>
            <SidebarGroupLabel>Firewalls</SidebarGroupLabel>
            <SidebarMenu>
              {fws.map((fw) => (
                <SidebarMenuItem key={fw.id}>
                  <NavFirewall fw={fw} />
                </SidebarMenuItem>
              ))}
              {fws.length === 0 && <div className="px-2 text-xs text-muted-foreground">Noch keine angelegt</div>}
            </SidebarMenu>
          </SidebarGroup>
          {isAdmin && (
            <SidebarGroup>
              <SidebarGroupLabel>Verwaltung</SidebarGroupLabel>
              <SidebarMenu>
                <NavLinkItem to="/admin/firewalls" icon={Settings2}>Firewalls verwalten</NavLinkItem>
                <NavLinkItem to="/admin/users" icon={Users}>Benutzer</NavLinkItem>
              </SidebarMenu>
            </SidebarGroup>
          )}
        </SidebarContent>
        <SidebarFooter>
          <div className="px-2 text-[10px] text-muted-foreground group-data-[collapsible=icon]:hidden">v0.1 · {fws.length} Firewall(s)</div>
        </SidebarFooter>
        <SidebarRail />
      </Sidebar>

      <SidebarInset className="min-w-0 print:m-0 print:shadow-none">
        <header className="sticky top-0 z-20 flex h-14 items-center gap-2 border-b bg-background/70 px-4 backdrop-blur-md print:hidden">
          <SidebarTrigger className="-ml-1" />
          <Separator orientation="vertical" className="mr-1 h-4" />
          <CommandMenu firewalls={fws} isAdmin={isAdmin} />
          <div className="ml-auto flex items-center gap-1">
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
              aria-label={theme === "dark" ? "Hellen Modus aktivieren" : "Dunklen Modus aktivieren"}
            >
              {theme === "dark" ? <Sun /> : <Moon />}
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" className="gap-2 px-2">
                  <Avatar className="size-7">
                    <AvatarFallback className="bg-primary/15 text-xs text-primary">
                      {user.username.slice(0, 2).toUpperCase()}
                    </AvatarFallback>
                  </Avatar>
                  <span className="hidden text-sm sm:inline">{user.username}</span>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-52">
                <DropdownMenuLabel className="font-normal">
                  <div className="text-sm font-medium">{user.username}</div>
                  <div className="text-xs text-muted-foreground">{isAdmin ? "Administrator" : "Betrachter"}</div>
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem asChild>
                  <Link to="/account"><KeyRound />Konto &amp; 2FA</Link>
                </DropdownMenuItem>
                <DropdownMenuItem onClick={logout} variant="destructive">
                  <LogOut />Abmelden
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </header>
        <main className="mx-auto w-full max-w-[1600px] flex-1 p-4 md:p-6 print:p-0">
          <Outlet />
        </main>
      </SidebarInset>
      <Toaster richColors position="bottom-right" />
    </SidebarProvider>
  );
}

function NavFirewall({ fw }: { fw: Firewall }) {
  const { pathname } = useLocation();
  const status = overallStatus(fw);
  return (
    <SidebarMenuButton asChild isActive={pathname.startsWith(`/firewalls/${fw.id}`)} tooltip={fw.name}>
      <Link to={`/firewalls/${fw.id}`}>
        <Server />
        <span className="truncate">{fw.name}</span>
        <span className={cn("ml-auto size-2 shrink-0 rounded-full", STATUS_DOT[status])} aria-label={`Status: ${status}`} />
      </Link>
    </SidebarMenuButton>
  );
}
