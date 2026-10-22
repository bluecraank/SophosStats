import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode, type ReactNode } from "react";
import { createRoot } from "react-dom/client";
import { createBrowserRouter, Navigate } from "react-router";
import { RouterProvider } from "react-router/dom";
import { Layout } from "./components/Layout";
import { TooltipProvider } from "./components/ui/tooltip";
import "./index.css";
import { ApiError } from "./lib/api";
import { AuthProvider, useAuth } from "./lib/auth";
import { AccountPage } from "./pages/AccountPage";
import { AdminFirewallsPage } from "./pages/AdminFirewallsPage";
import { DashboardPage } from "./pages/DashboardPage";
import { FirewallPage } from "./pages/FirewallPage";
import { LoginPage } from "./pages/LoginPage";
import { LogsPage } from "./pages/LogsPage";
import { ComparePage } from "./pages/ComparePage";
import { CrossSitePage } from "./pages/CrossSitePage";
import { TroubleshootPage } from "./pages/TroubleshootPage";
import { ReportPage } from "./pages/ReportPage";
import { UsersPage } from "./pages/UsersPage";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 15_000,
      // Kein Neuladen bei jedem Fensterwechsel – Seiten mit Live-Daten haben eigene Intervalle
      refetchOnWindowFocus: false,
      // 401/403/404 nicht wiederholen
      retry: (count, err) => !(err instanceof ApiError && err.status < 500) && count < 2,
    },
  },
});

function AdminOnly({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  return user?.role === "admin" ? children : <Navigate to="/" replace />;
}

const router = createBrowserRouter([
  { path: "/login", element: <LoginPage /> },
  {
    element: <Layout />,
    children: [
      { index: true, element: <DashboardPage /> },
      { path: "logs", element: <LogsPage /> },
      { path: "firewalls/:id", element: <FirewallPage /> },
      { path: "firewalls/:id/report", element: <ReportPage /> },
      { path: "compare", element: <ComparePage /> },
      { path: "cross-site", element: <CrossSitePage /> },
      { path: "troubleshoot", element: <TroubleshootPage /> },
      { path: "account", element: <AccountPage /> },
      { path: "admin/firewalls", element: <AdminOnly><AdminFirewallsPage /></AdminOnly> },
      { path: "admin/users", element: <AdminOnly><UsersPage /></AdminOnly> },
      { path: "*", element: <Navigate to="/" replace /> },
    ],
  },
]);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <TooltipProvider delayDuration={200}>
          <RouterProvider router={router} />
        </TooltipProvider>
      </AuthProvider>
    </QueryClientProvider>
  </StrictMode>,
);
