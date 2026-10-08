import { describe, expect, it, vi } from 'vitest';
import {
  apiRequest,
  getAlerts,
  getCurrentUser,
  getApiErrorMessage,
  login,
  subscribeUnauthorized,
} from '../src/services/api';
import {
  deferred,
  json,
  mockApi,
  TOKEN,
  TOKEN_KEY,
} from './http';

describe('API client with test-only responses', () => {
  it('sends login credentials without Authorization and stores JWT', async () => {
    const fetchMock = mockApi();
    await login('test.user', 'test-password');

    expect(localStorage.getItem(TOKEN_KEY)).toBe(TOKEN);
    const init = fetchMock.mock.calls[0][1]!;
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({
      username: 'test.user',
      password: 'test-password',
    });
    expect(init.headers).not.toHaveProperty('Authorization');
  });

  it('restores the user with the stored bearer token', async () => {
    localStorage.setItem(TOKEN_KEY, TOKEN);
    const fetchMock = mockApi();

    await expect(getCurrentUser()).resolves.toEqual({
      username: 'test.user',
      role: 'ADMIN',
    });
    expect(fetchMock.mock.calls[0][1]?.headers).toHaveProperty(
      'Authorization',
      `Bearer ${TOKEN}`,
    );
  });

  it('does not request protected endpoints without a token', async () => {
    const fetchMock = mockApi();

    await expect(getCurrentUser()).rejects.toMatchObject({
      code: 'NOT_AUTHENTICATED',
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('uses safe invalid-credentials feedback for login 401', async () => {
    mockApi({
      '/auth/login': () => json({ detail: 'private backend detail' }, 401),
    });

    await expect(login('test.user', 'wrong')).rejects.toMatchObject({
      code: 'INVALID_CREDENTIALS',
      message: 'Invalid username or password.',
    });
    expect(localStorage.getItem(TOKEN_KEY)).toBeNull();
  });

  it.each([400, 422])(
    'recognizes familiar login validation on HTTP %s',
    async status => {
      mockApi({
        '/auth/login': () => json({
          detail: 'Incorrect username or password',
        }, status),
      });

      await expect(login('test.user', 'wrong')).rejects.toMatchObject({
        code: 'INVALID_CREDENTIALS',
      });
    },
  );

  it('confirmed 401 clears JWT and notifies once for concurrent requests', async () => {
    localStorage.setItem(TOKEN_KEY, TOKEN);
    const held = deferred<Response>();
    mockApi({ '/auth/me': () => held.promise });
    const listener = vi.fn();
    const unsubscribe = subscribeUnauthorized(listener);

    try {
      const requests = Promise.allSettled([
        getCurrentUser(),
        getCurrentUser(),
      ]);
      held.resolve(json({}, 401));
      const results = await requests;

      expect(results.every(result => result.status === 'rejected')).toBe(true);
      expect(localStorage.getItem(TOKEN_KEY)).toBeNull();
      expect(listener).toHaveBeenCalledTimes(1);
    } finally {
      unsubscribe();
    }
  });

  it('an old request 401 cannot clear a replacement session', async () => {
    localStorage.setItem(TOKEN_KEY, TOKEN);
    const held = deferred<Response>();
    mockApi({ '/auth/me': () => held.promise });

    const result = getCurrentUser().catch(error => error);
    localStorage.setItem(TOKEN_KEY, 'replacement-test-token');
    held.resolve(json({}, 401));

    expect(await result).toMatchObject({ code: 'UNAUTHORIZED' });
    expect(localStorage.getItem(TOKEN_KEY)).toBe('replacement-test-token');
  });

  it.each([
    [403, 'FORBIDDEN', 'You do not have permission to perform this action.'],
    [429, 'RATE_LIMITED', 'Too many requests. Please wait and try again.'],
    [503, 'SERVICE_UNAVAILABLE', 'AISOP server is temporarily unavailable. Please try again.'],
  ])(
    'HTTP %s preserves JWT and ignores private response details',
    async (status, code, message) => {
      localStorage.setItem(TOKEN_KEY, TOKEN);
      mockApi({
        '/auth/me': () => json({
          detail: 'private backend detail',
        }, status as number),
      });

      const listener = vi.fn();
      const unsubscribe = subscribeUnauthorized(listener);
      try {
        await expect(getCurrentUser()).rejects.toMatchObject({
          code,
          message,
        });
        expect(localStorage.getItem(TOKEN_KEY)).toBe(TOKEN);
        expect(listener).not.toHaveBeenCalled();
      } finally {
        unsubscribe();
      }
    },
  );

  it('network failure uses a safe message and preserves JWT', async () => {
    localStorage.setItem(TOKEN_KEY, TOKEN);
    mockApi({
      '/auth/me': () => {
        throw new TypeError('private connection detail');
      },
    });

    await expect(getCurrentUser()).rejects.toMatchObject({
      code: 'NETWORK_ERROR',
      message: 'Unable to connect to AISOP server.',
    });
    expect(localStorage.getItem(TOKEN_KEY)).toBe(TOKEN);
  });

  it('times out after ten seconds and aborts without removing JWT', async () => {
    vi.useFakeTimers();
    localStorage.setItem(TOKEN_KEY, TOKEN);
    const held = deferred<Response>();
    const fetchMock = mockApi({ '/auth/me': () => held.promise });

    const result = getCurrentUser().catch(error => error);
    await vi.advanceTimersByTimeAsync(10_000);

    expect(await result).toMatchObject({ code: 'TIMEOUT' });
    expect(fetchMock.mock.calls[0][1]?.signal?.aborted).toBe(true);
    expect(localStorage.getItem(TOKEN_KEY)).toBe(TOKEN);
    held.resolve(json({}));
  });

  it('applies the deadline to a stalled success response body', async () => {
    vi.useFakeTimers();
    localStorage.setItem(TOKEN_KEY, TOKEN);
    const body = deferred<unknown>();
    const response = json({});
    vi.spyOn(response, 'json').mockImplementation(() => body.promise);
    mockApi({ '/auth/me': () => response });

    const result = getCurrentUser().catch(error => error);
    await vi.advanceTimersByTimeAsync(10_000);

    expect(await result).toMatchObject({
      code: 'TIMEOUT',
      status: 200,
    });
    expect(localStorage.getItem(TOKEN_KEY)).toBe(TOKEN);
    body.resolve({});
  });

  it('caller cancellation preserves JWT', async () => {
    localStorage.setItem(TOKEN_KEY, TOKEN);
    const held = deferred<Response>();
    mockApi({ '/auth/me': () => held.promise });
    const controller = new AbortController();

    const result = getCurrentUser(controller.signal).catch(error => error);
    controller.abort();

    expect(await result).toMatchObject({ code: 'CANCELLED' });
    expect(localStorage.getItem(TOKEN_KEY)).toBe(TOKEN);
    held.resolve(json({}));
  });

  it('malformed JSON returns a safe error without logout', async () => {
    localStorage.setItem(TOKEN_KEY, TOKEN);
    mockApi({
      '/auth/me': () => new Response('{broken', { status: 200 }),
    });

    await expect(getCurrentUser()).rejects.toMatchObject({
      code: 'INVALID_RESPONSE',
    });
    expect(localStorage.getItem(TOKEN_KEY)).toBe(TOKEN);
  });

  it('encodes severity and pagination in the request', async () => {
    localStorage.setItem(TOKEN_KEY, TOKEN);
    const fetchMock = mockApi();

    await getAlerts({ severity: 'high', limit: 10, offset: 20 });
    const url = new URL(String(fetchMock.mock.calls[0][0]));

    expect(Object.fromEntries(url.searchParams)).toEqual({
      severity: 'high',
      limit: '10',
      offset: '20',
    });
  });

  it('unknown errors never expose their original message', () => {
    expect(getApiErrorMessage(new Error('private detail'))).toBe(
      'Unable to complete your request. Please try again.',
    );
  });

  it('handles a 204 response without parsing JSON', async () => {
    localStorage.setItem(TOKEN_KEY, TOKEN);
    mockApi({
      '/auth/me': () => new Response(null, { status: 204 }),
    });

    await expect(apiRequest('/auth/me')).resolves.toBeUndefined();
  });
});
