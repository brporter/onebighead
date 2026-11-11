import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiClient, ApiError, api } from '../src/api/client';

function mockFetch401(body: unknown) {
  return vi.fn().mockResolvedValue(
    new Response(JSON.stringify(body), {
      status: 401,
      statusText: 'Unauthorized',
      headers: { 'Content-Type': 'application/json' },
    })
  );
}

describe('ApiClient 401 handling', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('passes the typed error code from the response body to onUnauthorized', async () => {
    vi.stubGlobal('fetch', mockFetch401({ code: 'SessionRevoked', error: 'revoked' }));
    const onUnauthorized = vi.fn();
    const client = new ApiClient({ baseUrl: '/api', onUnauthorized });

    await expect(client.get('/items')).rejects.toBeInstanceOf(ApiError);

    expect(onUnauthorized).toHaveBeenCalledWith('SessionRevoked');
  });

  it('passes undefined to onUnauthorized when the 401 body has no code', async () => {
    vi.stubGlobal('fetch', mockFetch401({ error: 'nope' }));
    const onUnauthorized = vi.fn();
    const client = new ApiClient({ baseUrl: '/api', onUnauthorized });

    await expect(client.get('/items')).rejects.toBeInstanceOf(ApiError);

    expect(onUnauthorized).toHaveBeenCalledWith(undefined);
  });

  it('routes USER_DELETED codes to onUserDeleted, not onUnauthorized', async () => {
    vi.stubGlobal('fetch', mockFetch401({ code: 'USER_DELETED' }));
    const onUnauthorized = vi.fn();
    const onUserDeleted = vi.fn();
    const client = new ApiClient({ baseUrl: '/api', onUnauthorized, onUserDeleted });

    await expect(client.get('/items')).rejects.toBeInstanceOf(ApiError);

    expect(onUserDeleted).toHaveBeenCalledOnce();
    expect(onUnauthorized).not.toHaveBeenCalled();
  });
});

describe('api singleton 401 handling', () => {
  let fakeLocation: { pathname: string; search: string; href: string };

  beforeEach(() => {
    fakeLocation = { pathname: '/collections', search: '', href: '' };
    vi.stubGlobal('location', fakeLocation);
    vi.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('redirects to the sign-in page when the session was revoked', async () => {
    vi.stubGlobal('fetch', mockFetch401({ code: 'SessionRevoked' }));

    await expect(api.get('/items')).rejects.toBeInstanceOf(ApiError);

    expect(fakeLocation.href).toBe('/signin?errorType=SessionRevoked&returnUrl=%2Fcollections');
  });

  it('does not redirect on a generic 401', async () => {
    vi.stubGlobal('fetch', mockFetch401({ error: 'not signed in' }));

    await expect(api.get('/items')).rejects.toBeInstanceOf(ApiError);

    expect(fakeLocation.href).toBe('');
  });

  it.each(['USER_DELETED', 'NO_ACTIVE_WORKSPACES'])('logs out and redirects after %s', async (code) => {
    const send = mockFetch401({ code }).mockResolvedValueOnce(
      Response.json({ code }, { status: 401 }),
    ).mockResolvedValueOnce(new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', send);

    await expect(api.get('/items')).rejects.toBeInstanceOf(ApiError);
    await vi.waitFor(() => expect(fakeLocation.href).toBe('/'));
    expect(send).toHaveBeenCalledTimes(2);
    expect(send).toHaveBeenLastCalledWith('/api/auth/logout', expect.objectContaining({ method: 'POST', credentials: 'include' }));
  });

  it('redirects without a recursive logout when cleanup also returns a deleted-account error', async () => {
    const send = vi.fn().mockImplementation(async () => Response.json({ code: 'USER_DELETED' }, { status: 401 }));
    vi.stubGlobal('fetch', send);

    await expect(api.get('/items')).rejects.toBeInstanceOf(ApiError);
    await vi.waitFor(() => expect(fakeLocation.href).toBe('/'));
    expect(send).toHaveBeenCalledTimes(2);
  });

  it('redirects even if the logout connection fails', async () => {
    const send = mockFetch401({ code: 'USER_DELETED' })
      .mockResolvedValueOnce(Response.json({ code: 'USER_DELETED' }, { status: 401 }))
      .mockRejectedValueOnce(new Error('offline'));
    vi.stubGlobal('fetch', send);

    await expect(api.get('/items')).rejects.toBeInstanceOf(ApiError);
    await vi.waitFor(() => expect(fakeLocation.href).toBe('/'));
    expect(send).toHaveBeenCalledTimes(2);
  });
});
