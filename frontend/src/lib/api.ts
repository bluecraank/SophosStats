export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

type Params = Record<string, string | number | boolean | null | undefined | string[]>;

function buildUrl(path: string, params?: Params): string {
  const url = new URL(path, window.location.origin);
  for (const [key, value] of Object.entries(params ?? {})) {
    if (value === undefined || value === null || value === "") continue;
    if (Array.isArray(value)) value.forEach((v) => url.searchParams.append(key, v));
    else url.searchParams.set(key, String(value));
  }
  return url.pathname + url.search;
}

export async function api<T>(
  path: string,
  options: { method?: string; body?: unknown; params?: Params } = {},
): Promise<T> {
  const res = await fetch(buildUrl(path, options.params), {
    method: options.method ?? "GET",
    credentials: "same-origin",
    headers: {
      // Wird vom Backend als CSRF-Schutz für schreibende Requests verlangt
      "X-Requested-With": "SophosStats",
      ...(options.body !== undefined ? { "Content-Type": "application/json" } : {}),
    },
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
  });

  if (!res.ok) {
    let message = res.statusText;
    try {
      const data = await res.json();
      if (typeof data.detail === "string") message = data.detail;
      else if (Array.isArray(data.detail)) message = data.detail.map((d: { msg: string }) => d.msg).join(", ");
    } catch {
      /* keine JSON-Antwort */
    }
    if (res.status === 401 && !path.endsWith("/auth/login")) {
      window.dispatchEvent(new Event("auth:expired"));
    }
    throw new ApiError(res.status, message);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}
