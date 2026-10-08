import { StrictMode } from 'react';
import {
  act, fireEvent, render, screen, waitFor, within,
} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import App from '../src/App';
import {
  alert, deferred, json, mockApi, statistics, TOKEN, TOKEN_KEY,
} from './http';

async function restored(
  role = 'ADMIN',
  routes: Parameters<typeof mockApi>[0] = {},
) {
  localStorage.setItem(TOKEN_KEY, TOKEN);
  const fetchMock = mockApi(routes, role);
  render(<App />);
  await screen.findByRole('heading', { name: 'Security Overview' });
  return fetchMock;
}

function nav(name: RegExp | string) {
  return within(
    screen.getByRole('navigation', { name: 'Main navigation' }),
  ).getByRole('button', { name });
}

function section(label: string) {
  return document.querySelector(`[data-section="${label}"]`);
}

async function signIn() {
  const user = userEvent.setup();
  await user.type(
    await screen.findByPlaceholderText('Enter your username'),
    'test.user',
  );
  await user.type(
    screen.getByPlaceholderText('Enter your password'),
    'test-password',
  );
  await user.click(
    screen.getByRole('button', { name: 'Sign in securely' }),
  );
}

describe('authentication and login appearance behavior', () => {
  it('does not fetch protected data before authentication', async () => {
    const fetchMock = mockApi();
    render(<App />);
    await screen.findByPlaceholderText('Enter your username');

    expect(fetchMock).not.toHaveBeenCalled();
    expect(
      screen.getByRole('button', { name: 'Sign in securely' }),
    ).toBeDisabled();
  });

  it('successful login verifies the user before showing protected data', async () => {
    const fetchMock = mockApi();
    render(<App />);
    await signIn();
    await screen.findByRole('heading', { name: 'Security Overview' });

    expect(localStorage.getItem(TOKEN_KEY)).toBe(TOKEN);
    expect(
      fetchMock.mock.calls.slice(0, 2).map(
        call => new URL(String(call[0])).pathname,
      ),
    ).toEqual(['/api/v1/auth/login', '/api/v1/auth/me']);
    await screen.findByText(alert.title);
  });

  it('failed login stays on the form with safe feedback', async () => {
    mockApi({
      '/auth/login': () => json({ detail: 'private detail' }, 401),
    });
    render(<App />);
    await signIn();

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Invalid username or password.',
    );
    expect(screen.queryByRole('navigation')).not.toBeInTheDocument();
    expect(localStorage.getItem(TOKEN_KEY)).toBeNull();
  });

  it('restores a stored JWT under StrictMode', async () => {
    localStorage.setItem(TOKEN_KEY, TOKEN);
    mockApi();
    render(<StrictMode><App /></StrictMode>);

    await screen.findByRole('heading', { name: 'Security Overview' });
    await screen.findByText(alert.title);
    expect(localStorage.getItem(TOKEN_KEY)).toBe(TOKEN);
  });

  it('confirmed protected 401 returns to login', async () => {
    let expired = false;
    await restored('ADMIN', {
      '/alerts': () => expired
        ? json({}, 401)
        : json({ count: 1, limit: 10, offset: 0, alerts: [alert] }),
    });
    await screen.findByText(alert.title);

    expired = true;
    await userEvent.setup().click(
      screen.getByRole('button', { name: 'Refresh' }),
    );
    await screen.findByPlaceholderText('Enter your username');

    expect(screen.getByRole('alert')).toHaveTextContent(
      'Your session has expired.',
    );
    expect(localStorage.getItem(TOKEN_KEY)).toBeNull();
  });

  it.each([403, 429])(
    'restoration HTTP %s preserves JWT and permits retry',
    async status => {
      localStorage.setItem(TOKEN_KEY, TOKEN);
      let failing = true;
      mockApi({
        '/auth/me': () => failing
          ? json({ detail: 'private detail' }, status)
          : json({ username: 'test.user', role: 'ADMIN' }),
      });
      render(<App />);

      await screen.findByRole('heading', {
        name: 'Unable to verify session',
      });
      expect(localStorage.getItem(TOKEN_KEY)).toBe(TOKEN);
      expect(screen.queryByRole('navigation')).not.toBeInTheDocument();

      failing = false;
      await userEvent.setup().click(
        screen.getByRole('button', { name: 'Retry Connection' }),
      );
      await screen.findByRole('heading', { name: 'Security Overview' });
    },
  );

  it('network restoration failure retains JWT and reconnects', async () => {
    localStorage.setItem(TOKEN_KEY, TOKEN);
    let failing = true;
    mockApi({
      '/auth/me': () => {
        if (failing) throw new TypeError('private detail');
        return json({ username: 'test.user', role: 'ADMIN' });
      },
    });
    render(<App />);

    await screen.findByRole('heading', {
      name: 'AISOP server unavailable',
    });
    expect(localStorage.getItem(TOKEN_KEY)).toBe(TOKEN);

    failing = false;
    await userEvent.setup().click(
      screen.getByRole('button', { name: 'Retry Connection' }),
    );
    await screen.findByRole('heading', { name: 'Security Overview' });
  });

  it('restoration timeout shows connection recovery while keeping the token', async () => {
    vi.useFakeTimers();
    localStorage.setItem(TOKEN_KEY, TOKEN);
    const held = deferred<Response>();
    mockApi({ '/auth/me': () => held.promise });

    await act(async () => { render(<App />); });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000);
    });

    expect(
      screen.getByRole('heading', { name: 'AISOP server unavailable' }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Retry Connection' }),
    ).toBeEnabled();
    expect(localStorage.getItem(TOKEN_KEY)).toBe(TOKEN);

    await act(async () => {
      held.resolve(json({ username: 'test.user', role: 'ADMIN' }));
    });
    expect(screen.queryByRole('navigation')).not.toBeInTheDocument();
  });

  it('explicit logout clears JWT and returns to login', async () => {
    await restored();
    await screen.findByText(alert.title);
    const user = userEvent.setup();

    await user.click(
      screen.getByRole('button', { name: /test.user ADMIN/ }),
    );
    await user.click(screen.getByRole('menuitem', { name: 'Logout' }));
    await screen.findByPlaceholderText('Enter your username');

    expect(localStorage.getItem(TOKEN_KEY)).toBeNull();
  });

  it('theme persists through login and password visibility remains usable', async () => {
    localStorage.setItem('aisop-theme', 'light');
    mockApi();
    const view = render(<App />);
    await screen.findByPlaceholderText('Enter your password');
    const user = userEvent.setup();

    expect(view.container.querySelector('.app-shell')).toHaveAttribute(
      'data-theme', 'light',
    );

    await user.click(screen.getByRole('button', { name: 'Show password' }));
    expect(
      screen.getByPlaceholderText('Enter your password'),
    ).toHaveAttribute('type', 'text');

    await user.click(screen.getByRole('button', { name: 'Hide password' }));
    expect(
      screen.getByPlaceholderText('Enter your password'),
    ).toHaveAttribute('type', 'password');

    await user.click(
      screen.getByRole('button', { name: 'Switch to dark mode' }),
    );
    await signIn();
    await screen.findByRole('heading', { name: 'Security Overview' });

    expect(view.container.querySelector('.app-shell')).toHaveAttribute(
      'data-theme', 'dark',
    );
    expect(localStorage.getItem('aisop-theme')).toBe('dark');
  });
});

describe('roles', () => {
  it.each(['ADMIN', 'ANALYST', 'VIEWER'])(
    '%s receives its existing UI permissions',
    async role => {
      const fetchMock = await restored(role);
      await screen.findByText(alert.title);
      const user = userEvent.setup();
      const navigation = within(screen.getByRole('navigation'));

      if (role === 'ADMIN') {
        expect(
          navigation.getByRole('button', { name: 'Settings' }),
        ).toBeEnabled();
      } else {
        expect(
          navigation.queryByRole('button', { name: 'Settings' }),
        ).not.toBeInTheDocument();
      }

      const statisticsRequests = fetchMock.mock.calls.filter(
        call => String(call[0]).endsWith('/statistics'),
      );
      expect(statisticsRequests.length > 0).toBe(role !== 'VIEWER');

      await user.click(nav('Detection Rules'));
      if (role === 'ADMIN') {
        await user.click(
          screen.getByRole('button', { name: 'Create Rule' }),
        );
        expect(
          screen.getByRole('dialog', { name: 'Create detection rule' }),
        ).toBeInTheDocument();
        await user.click(screen.getByRole('button', { name: 'Cancel' }));
      } else {
        expect(
          screen.queryByRole('button', { name: 'Create Rule' }),
        ).not.toBeInTheDocument();
        screen.getAllByRole('button', { name: 'Edit' }).forEach(
          button => expect(button).toBeDisabled(),
        );
      }

      await user.click(nav('Investigations'));
      await user.click(
        screen.getByText('Potential SSH brute force & access'),
      );
      const notes = screen.getByLabelText('Analyst notes');
      expect(notes).toHaveProperty('readOnly', role === 'VIEWER');

      if (role === 'VIEWER') {
        expect(
          screen.getByRole('button', { name: 'Save note' }),
        ).toBeDisabled();
        expect(
          screen.queryByLabelText('Investigation status'),
        ).not.toBeInTheDocument();
      } else {
        await user.selectOptions(
          screen.getByLabelText('Investigation status'), 'Resolved',
        );
        expect(
          screen.getByLabelText('Investigation status'),
        ).toHaveValue('Resolved');
      }
    },
  );
});

describe('alerts, statistics and recovery', () => {
  it('shows loading independently and renders alerts while statistics remain pending', async () => {
    const held = deferred<Response>();
    await restored('ADMIN', { '/statistics': () => held.promise });
    await screen.findByText(alert.title);

    expect(section('statistics')).toHaveTextContent('Loading');
    await act(async () => { held.resolve(json(statistics)); });
    await waitFor(() => expect(section('statistics')).toBeNull());
    expect(
      screen.getByRole('button', { name: /Total Alerts/ }),
    ).toHaveTextContent('12');
  });

  it('shows alerts loading, then the empty response without sample alerts', async () => {
    const held = deferred<Response>();
    await restored('ADMIN', { '/alerts': () => held.promise });

    expect(section('alerts')).toHaveTextContent('Loading');
    expect(screen.queryByText(alert.title)).not.toBeInTheDocument();

    await act(async () => {
      held.resolve(json({ count: 0, limit: 10, offset: 0, alerts: [] }));
    });
    await screen.findByText('No alerts found');
  });

  it('zero statistics show the empty state', async () => {
    await restored('ADMIN', {
      '/statistics': () => json({
        total_alerts: 0,
        severity: { high: 0, medium: 0, low: 0 },
      }),
    });

    await screen.findByText('Statistics: No alerts recorded.');
    expect(
      screen.getByRole('button', { name: /Total Alerts/ }),
    ).toHaveTextContent('0');
  });

  it('statistics 403 preserves session while alerts remain visible', async () => {
    await restored('ADMIN', { '/statistics': () => json({}, 403) });
    await screen.findByText(alert.title);

    await waitFor(() => {
      expect(section('statistics')).toHaveTextContent(
        'Statistics are unavailable for your role. Alerts remain available.',
      );
    });
    expect(localStorage.getItem(TOKEN_KEY)).toBe(TOKEN);
  });

  it.each([429, 503])(
    'alerts HTTP %s does not hide successful statistics or log out',
    async status => {
      await restored('ADMIN', {
        '/alerts': () => json({ detail: 'private detail' }, status),
      });

      await screen.findByRole('button', { name: 'Retry Alerts' });
      await waitFor(() => {
        expect(
          screen.getByRole('button', { name: /Total Alerts/ }),
        ).toHaveTextContent('12');
      });
      expect(section('alerts')).not.toHaveTextContent('private detail');
      expect(localStorage.getItem(TOKEN_KEY)).toBe(TOKEN);
    },
  );

  it('pagination uses server offsets and severity resets pagination to page one', async () => {
    const fetchMock = await restored('ADMIN', {
      '/alerts': url => {
        const offset = Number(url.searchParams.get('offset'));
        const severity = url.searchParams.get('severity');
        return json({
          count: severity ? 1 : 11,
          limit: 10,
          offset,
          alerts: [{
            ...alert,
            id: offset + 101,
            title: severity
              ? 'Filtered high alert'
              : offset ? 'Page two alert' : alert.title,
          }],
        });
      },
    });

    await screen.findByText(alert.title);
    const user = userEvent.setup();
    await user.click(nav(/Events & Alerts/));

    expect(
      await within(screen.getByRole('table')).findByText(alert.title),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Previous' }),
    ).toBeDisabled();

    await user.click(screen.getByRole('button', { name: 'Next' }));
    await within(screen.getByRole('table')).findByText('Page two alert');
    expect(
      within(screen.getByRole('table')).queryByText(alert.title),
    ).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();

    await user.selectOptions(
      screen.getByLabelText('Filter by severity'), 'High',
    );
    await within(screen.getByRole('table')).findByText(
      'Filtered high alert',
    );
    expect(
      screen.getByRole('button', { name: 'Previous' }),
    ).toBeDisabled();

    const urls = fetchMock.mock.calls.map(
      call => new URL(String(call[0])),
    );
    expect(
      urls.some(url => url.searchParams.get('offset') === '10'),
    ).toBe(true);
    expect(urls.some(
      url => url.searchParams.get('severity') === 'high' &&
        url.searchParams.get('offset') === '0',
    )).toBe(true);

    await user.type(
      screen.getByPlaceholderText('Search events, hosts, IPs...'),
      'does-not-match',
    );
    await screen.findByText('No matching alerts on this page');
    await user.click(screen.getByRole('button', { name: 'Clear search' }));
    await within(screen.getByRole('table')).findByText(
      'Filtered high alert',
    );
  });

  it('failed refresh retains stale results and section retry recovers', async () => {
    let failing = false;
    await restored('ADMIN', {
      '/alerts': () => failing
        ? json({}, 503)
        : json({ count: 1, limit: 10, offset: 0, alerts: [alert] }),
      '/statistics': () => failing ? json({}, 503) : json(statistics),
    });
    await screen.findByText(alert.title);
    await waitFor(() => expect(section('statistics')).toBeNull());

    failing = true;
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Refresh' }));
    await screen.findByRole('button', { name: 'Retry Alerts' });

    expect(section('alerts')).toHaveTextContent('Stale data');
    expect(section('statistics')).toHaveTextContent('Stale data');
    expect(screen.getByText(alert.title)).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: /Total Alerts/ }),
    ).toHaveTextContent('12');

    failing = false;
    await user.click(
      screen.getByRole('button', { name: 'Retry Alerts' }),
    );
    await waitFor(() => expect(section('alerts')).toBeNull());
    expect(section('statistics')).toHaveTextContent('Stale data');

    await user.click(
      screen.getByRole('button', { name: 'Retry Statistics' }),
    );
    await waitFor(() => expect(section('statistics')).toBeNull());
  });

  it('polls after five seconds and stops on unmount', async () => {
    vi.useFakeTimers();
    localStorage.setItem(TOKEN_KEY, TOKEN);
    const fetchMock = mockApi();
    let view!: ReturnType<typeof render>;
    await act(async () => { view = render(<App />); });

    expect(
      screen.getByRole('heading', { name: 'Security Overview' }),
    ).toBeInTheDocument();
    const count = () => fetchMock.mock.calls.filter(
      call => String(call[0]).includes('/alerts?'),
    ).length;
    const initial = count();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(4999);
    });
    expect(count()).toBe(initial);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1);
    });
    expect(count()).toBe(initial + 1);

    view.unmount();
    const afterUnmount = fetchMock.mock.calls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(15_000);
    });
    expect(fetchMock).toHaveBeenCalledTimes(afterUnmount);
  });

  it('polling and retry do not overlap an in-flight alerts request', async () => {
    vi.useFakeTimers();
    localStorage.setItem(TOKEN_KEY, TOKEN);
    const held = deferred<Response>();
    const fetchMock = mockApi({ '/alerts': () => held.promise });
    await act(async () => { render(<App />); });

    const count = () => fetchMock.mock.calls.filter(
      call => String(call[0]).includes('/alerts?'),
    ).length;
    expect(count()).toBe(1);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });
    expect(count()).toBe(1);

    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    expect(count()).toBe(1);

    await act(async () => {
      held.resolve(json({
        count: 1, limit: 10, offset: 0, alerts: [alert],
      }));
    });
    expect(screen.getByText(alert.title)).toBeInTheDocument();
  });

  it('ignores a late old-query response after severity changes', async () => {
    const old = deferred<Response>();
    await restored('ADMIN', {
      '/alerts': url => url.searchParams.get('severity') === 'high'
        ? json({
          count: 1,
          limit: 10,
          offset: 0,
          alerts: [{ ...alert, title: 'Current high result' }],
        })
        : old.promise,
    });

    fireEvent.click(nav(/Events & Alerts/));
    fireEvent.change(
      screen.getByLabelText('Filter by severity'),
      { target: { value: 'High' } },
    );
    await within(screen.getByRole('table')).findByText(
      'Current high result',
    );

    await act(async () => {
      old.resolve(json({
        count: 1,
        limit: 10,
        offset: 0,
        alerts: [{ ...alert, title: 'Obsolete result' }],
      }));
    });

    expect(
      within(screen.getByRole('table')).queryByText('Obsolete result'),
    ).not.toBeInTheDocument();
    expect(
      within(screen.getByRole('table')).getByText('Current high result'),
    ).toBeInTheDocument();
  });
});
