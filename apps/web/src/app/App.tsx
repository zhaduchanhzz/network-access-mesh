import { QueryClientProvider, type QueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { createBrowserRouter, RouterProvider } from "react-router";
import { createQueryClient } from "../api/queryClient";
import { ThemeProvider } from "../theme/theme";
import { ConsoleProvider, consoleFromHost, type ConsoleKind } from "./console";
import { NoticesProvider } from "./notices";
import { routes } from "./routes";

/** createBrowserRouter và createMemoryRouter (test) trả cùng kiểu DataRouter */
type Router = ReturnType<typeof createBrowserRouter>;

export interface AppProps {
  /** test: router bộ nhớ + QueryClient + console cố định */
  router?: Router;
  queryClient?: QueryClient;
  console?: ConsoleKind;
}

export function App(props: AppProps) {
  const [queryClient] = useState(() => props.queryClient ?? createQueryClient());
  const [router] = useState(() => props.router ?? createBrowserRouter(routes));
  const kind = props.console ?? consoleFromHost(window.location.hostname);
  return (
    <QueryClientProvider client={queryClient}>
      <ConsoleProvider kind={kind}>
        <ThemeProvider>
          <NoticesProvider>
            <RouterProvider router={router} />
          </NoticesProvider>
        </ThemeProvider>
      </ConsoleProvider>
    </QueryClientProvider>
  );
}
