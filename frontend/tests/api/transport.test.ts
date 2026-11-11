import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiClient, ApiError } from '../../src/api/transport';
import { deferred } from '../testUtils/deferred';

function cancellableFetch() {
  return vi.fn<typeof fetch>().mockImplementation((_url, options) => {
    const signal = options!.signal!;
    return new Promise<Response>((_resolve, reject) => {
      const abort = () => reject(new DOMException('Aborted', 'AbortError'));
      if (signal.aborted) abort();
      else signal.addEventListener('abort', abort, { once: true });
    });
  });
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('HTTP request lifecycle', () => {
  it('keeps a replacement cancellable after the original request settles', async () => {
    const send = cancellableFetch();
    const client = new ApiClient({ baseUrl: '/api', fetch: send });
    const first = client.get('/first', {}, 'selection');
    const firstResult = expect(first).rejects.toMatchObject({ statusText: 'Aborted' });
    const second = client.get('/second', {}, 'selection');
    const secondResult = expect(second).rejects.toMatchObject({ statusText: 'Aborted' });

    await firstResult;
    expect(send.mock.calls[1][1]!.signal!.aborted).toBe(false);
    client.cancelRequest('selection');
    expect(send.mock.calls[1][1]!.signal!.aborted).toBe(true);
    await secondResult;
    client.cancelRequest('missing');
  });

  it('does not remove a replacement when an older adapter ignores cancellation', async () => {
    const old = deferred<Response>();
    const send = cancellableFetch().mockImplementationOnce(() => old.promise);
    const client = new ApiClient({ baseUrl: '/api', fetch: send });
    const first = client.get('/first', {}, 'selection');
    const second = client.get('/second', {}, 'selection');
    const secondResult = expect(second).rejects.toMatchObject({ statusText: 'Aborted' });
    old.resolve(Response.json({ id: 1 }));
    await first;

    client.cancelRequest('selection');
    expect(send.mock.calls[1][1]!.signal!.aborted).toBe(true);
    await secondResult;
  });

  it.each([false, true])('respects the caller signal (already aborted: %s)', async (alreadyAborted) => {
    const caller = new AbortController();
    if (alreadyAborted) caller.abort();
    const remove = vi.spyOn(caller.signal, 'removeEventListener');
    const client = new ApiClient({ baseUrl: '/api', fetch: cancellableFetch() });
    const request = client.get('/items', { signal: caller.signal });
    const result = expect(request).rejects.toMatchObject({ status: 0, statusText: 'Aborted' });
    caller.abort();

    await result;
    expect(remove).toHaveBeenCalledWith('abort', expect.any(Function));
  });

  it('releases the caller listener and timeout after success', async () => {
    vi.useFakeTimers();
    const caller = new AbortController();
    const remove = vi.spyOn(caller.signal, 'removeEventListener');
    const send = vi.fn<typeof fetch>().mockResolvedValue(Response.json({ id: 1 }));
    const client = new ApiClient({ baseUrl: '/api', fetch: send });

    await expect(client.get('/items', { signal: caller.signal }, 'selection')).resolves.toEqual({ id: 1 });
    caller.abort();
    client.cancelRequest('selection');
    expect(send.mock.calls[0][1]!.signal!.aborted).toBe(false);
    expect(remove).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('times out without aborting the caller controller', async () => {
    vi.useFakeTimers();
    const caller = new AbortController();
    const client = new ApiClient({ baseUrl: '/api', fetch: cancellableFetch() });
    const request = client.get('/slow', { signal: caller.signal, timeout: 50 });
    const result = expect(request).rejects.toMatchObject({ statusText: 'Aborted' });
    await vi.advanceTimersByTimeAsync(50);

    await result;
    expect(caller.signal.aborted).toBe(false);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('cleans up even when invalid headers prevent sending the request', async () => {
    vi.useFakeTimers();
    const caller = new AbortController();
    const remove = vi.spyOn(caller.signal, 'removeEventListener');
    const send = vi.fn<typeof fetch>();
    const client = new ApiClient({ baseUrl: '/api', fetch: send });

    await expect(client.get('/items', {
      headers: { 'invalid header': 'value' }, signal: caller.signal,
    }, 'selection')).rejects.toBeInstanceOf(ApiError);

    expect(send).not.toHaveBeenCalled();
    expect(remove).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
    client.cancelRequest('selection');
  });
});

describe('HTTP payloads and errors', () => {
  it.each(['post', 'put'] as const)('preserves falsy JSON values for %s', async (method) => {
    const send = vi.fn<typeof fetch>().mockImplementation(async () => new Response(null, { status: 204 }));
    const client = new ApiClient({ baseUrl: '/api', fetch: send });
    for (const value of [false, 0, '', null, undefined]) {
      await client[method]('/value', value);
      expect(send).toHaveBeenLastCalledWith('/api/value', expect.objectContaining({
        method: method.toUpperCase(), body: JSON.stringify(value), credentials: 'include',
      }));
    }
  });

  it('merges custom headers and preserves an explicit content type', async () => {
    const send = vi.fn<typeof fetch>().mockResolvedValue(Response.json({ ok: true }));
    const client = new ApiClient({
      baseUrl: '/api', fetch: send, defaultHeaders: { 'X-Default': 'kept', 'X-Override': 'old' },
    });
    await client.post('/items', {}, { headers: { 'X-Override': 'new', 'Content-Type': 'application/merge-patch+json' } });
    const headers = send.mock.calls[0][1]!.headers as Headers;
    expect(headers.get('X-Default')).toBe('kept');
    expect(headers.get('X-Override')).toBe('new');
    expect(headers.get('Content-Type')).toBe('application/merge-patch+json');
  });

  it('supports a bare request without options', async () => {
    const send = vi.fn<typeof fetch>().mockResolvedValue(Response.json({ ok: true }));
    await expect(new ApiClient({ baseUrl: '/api', fetch: send }).request('/items')).resolves.toEqual({ ok: true });
  });

  it.each([
    ['null', 'null'],
    ['{}', '{}'],
    ['""', '""'],
    ['service unavailable', 'service unavailable'],
    ['', 'Unavailable'],
  ])('uses a useful fallback for an error body of %s', async (body, message) => {
    const send = vi.fn<typeof fetch>().mockResolvedValue(new Response(body, { status: 503, statusText: 'Unavailable' }));
    await expect(new ApiClient({ baseUrl: '/api', fetch: send }).get('/items')).rejects.toMatchObject({ message, status: 503 });
  });

  it('falls back to the HTTP status if reading an error body fails', async () => {
    const response = new Response('', { status: 503, statusText: 'Unavailable' });
    vi.spyOn(response, 'text').mockRejectedValue(new Error('Connection closed'));
    const send = vi.fn<typeof fetch>().mockResolvedValue(response);
    await expect(new ApiClient({ baseUrl: '/api', fetch: send }).get('/items')).rejects.toMatchObject({ message: 'Unavailable' });
  });

  it.each([new DOMException('Blocked', 'SecurityError'), 'offline'])('normalizes non-HTTP failures (%s)', async (error) => {
    const send = vi.fn<typeof fetch>().mockRejectedValue(error);
    await expect(new ApiClient({ baseUrl: '/api', fetch: send }).get('/items')).rejects.toMatchObject({
      message: error instanceof Error ? error.message : 'Network error', status: 0, statusText: 'NetworkError',
    });
  });

  it.each(['USER_DELETED', 'NO_ACTIVE_WORKSPACES'])('falls back to unauthorized when %s has no specific handler', async (code) => {
    const send = vi.fn<typeof fetch>().mockResolvedValue(Response.json({ code }, { status: 401 }));
    const onUnauthorized = vi.fn();
    await expect(new ApiClient({ baseUrl: '/api', fetch: send, onUnauthorized }).get('/items')).rejects.toBeInstanceOf(ApiError);
    expect(onUnauthorized).toHaveBeenCalledWith(code);
  });

  it('routes missing workspaces to the specific handler', async () => {
    const send = vi.fn<typeof fetch>().mockResolvedValue(Response.json({ code: 'NO_ACTIVE_WORKSPACES' }, { status: 401 }));
    const onNoActiveWorkspaces = vi.fn();
    const onUnauthorized = vi.fn();
    await expect(new ApiClient({ baseUrl: '/api', fetch: send, onNoActiveWorkspaces, onUnauthorized }).get('/items')).rejects.toBeInstanceOf(ApiError);
    expect(onNoActiveWorkspaces).toHaveBeenCalledOnce();
    expect(onUnauthorized).not.toHaveBeenCalled();
  });
});
