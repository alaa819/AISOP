import { vi } from 'vitest';

export const TOKEN = 'test-only-token';
export const TOKEN_KEY = 'aisop_access_token';
export const statistics = {
  total_alerts: 12,
  severity: { high: 7, medium: 3, low: 2 },
};
export const alert = {
  id: 101,
  severity: 'high',
  title: 'Test SSH alert',
  host: 'test-host',
  status: 'Open',
  source: 'auth.log',
};

export function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

export function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}

export type Route = (
  url: URL,
  init?: RequestInit,
) => Response | Promise<Response>;

export function mockApi(
  overrides: Record<string, Route> = {},
  role = 'ADMIN',
) {
  const routes: Record<string, Route> = {
    '/auth/login': () => json({
      access_token: TOKEN,
      token_type: 'bearer',
    }),
    '/auth/me': () => json({ username: 'test.user', role }),
    '/statistics': () => json(statistics),
    '/alerts': url => json({
      count: 1,
      limit: 10,
      offset: Number(url.searchParams.get('offset')),
      alerts: [alert],
    }),
    ...overrides,
  };

  const fetchMock = vi.fn(async (
    input: RequestInfo | URL,
    init?: RequestInit,
  ) => {
    const url = new URL(String(input));
    if (
      url.origin !== 'http://127.0.0.1:8000' ||
      !url.pathname.startsWith('/api/v1/')
    ) {
      throw new Error('Unexpected API origin or path');
    }

    const route = routes[url.pathname.slice('/api/v1'.length)];
    if (!route) {
      throw new Error(`Unexpected endpoint: ${url.pathname}`);
    }
    return route(url, init);
  });

  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}
