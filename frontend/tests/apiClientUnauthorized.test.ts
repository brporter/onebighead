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
});
