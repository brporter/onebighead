import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor, act } from '@testing-library/react';
import { useAsyncData } from '../src/utils/useAsyncData';
import { useCallback } from 'react';
import { deferred } from './testUtils/deferred';
import { ApiError } from '../src/api/client';

describe('useAsyncData', () => {
  it('retries the current fetcher, cancels its previous request and preserves retry identity', async () => {
    let resolve!: (value: string) => void;
    const first = new Promise<string>(yes => { resolve = yes; });
    const fetcher = vi.fn().mockReturnValueOnce(first).mockRejectedValueOnce(new Error('Offline')).mockResolvedValue('Fresh');
    const { result } = renderHook(() => useAsyncData(fetcher));
    const retry = result.current.retry;
    const signal = fetcher.mock.calls[0][0] as AbortSignal;
    act(() => result.current.retry());
    await waitFor(() => expect(result.current.error).toBe('Offline'));
    expect(signal.aborted).toBe(true);
    await act(async () => resolve('Stale'));
    expect(result.current.data).toBeNull();
    act(() => result.current.retry());
    expect(result.current.loading).toBe(true);
    expect(result.current.error).toBeNull();
    await waitFor(() => expect(result.current.data).toBe('Fresh'));
    expect(result.current.retry).toBe(retry);
  });

  it('keeps an idle query idle when retried', () => {
    const { result } = renderHook(() => useAsyncData(null));
    act(() => result.current.retry());
    expect(result.current.loading).toBe(false);
    expect(result.current.error).toBeNull();
  });
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should start in loading state when fetcher is provided', () => {
    const fetcher = vi.fn(() => new Promise<string>(() => {}));

    const { result } = renderHook(() => useAsyncData(fetcher));

    expect(result.current.loading).toBe(true);
    expect(result.current.data).toBeNull();
    expect(result.current.error).toBeNull();
  });

  it('should start in idle state when fetcher is null', () => {
    const { result } = renderHook(() => useAsyncData<string>(null));

    expect(result.current.loading).toBe(false);
    expect(result.current.data).toBeNull();
    expect(result.current.error).toBeNull();
  });

  it('should set data on successful fetch', async () => {
    const fetcher = vi.fn(() => Promise.resolve('hello'));

    const { result } = renderHook(() => useAsyncData(fetcher));

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.data).toBe('hello');
    expect(result.current.error).toBeNull();
  });

  it('should set error on failed fetch', async () => {
    const fetcher = vi.fn(() => Promise.reject(new Error('fail')));

    const { result } = renderHook(() => useAsyncData(fetcher));

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.data).toBeNull();
    expect(result.current.error).toBe('fail');
  });

  it('should handle non-Error rejections', async () => {
    const fetcher = vi.fn(() => Promise.reject('string error'));

    const { result } = renderHook(() => useAsyncData(fetcher));

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.error).toBe('An error occurred');
  });

  it('should refetch when fetcher identity changes', async () => {
    let resolveFirst: (val: string) => void;
    let resolveSecond: (val: string) => void;

    const firstFetcher = vi.fn(() => new Promise<string>((resolve) => { resolveFirst = resolve; }));
    const secondFetcher = vi.fn(() => new Promise<string>((resolve) => { resolveSecond = resolve; }));

    const { result, rerender } = renderHook(
      ({ fn }) => useAsyncData(fn),
      { initialProps: { fn: firstFetcher } },
    );

    // Resolve first
    await act(async () => { resolveFirst!('first'); });
    await waitFor(() => expect(result.current.data).toBe('first'));

    // Change fetcher
    rerender({ fn: secondFetcher });

    await waitFor(() => expect(result.current.loading).toBe(true));

    await act(async () => { resolveSecond!('second'); });
    await waitFor(() => expect(result.current.data).toBe('second'));
  });

  it('should cancel previous fetch when fetcher changes', async () => {
    let resolveFirst: (val: string) => void;
    const firstFetcher = vi.fn(() => new Promise<string>((resolve) => { resolveFirst = resolve; }));
    const secondFetcher = vi.fn(() => Promise.resolve('second'));

    const { result, rerender } = renderHook(
      ({ fn }) => useAsyncData(fn),
      { initialProps: { fn: firstFetcher } },
    );

    // Change fetcher before first resolves
    rerender({ fn: secondFetcher });

    await waitFor(() => expect(result.current.data).toBe('second'));

    // Resolve first fetch late - should be ignored
    await act(async () => { resolveFirst!('first'); });

    // Data should still be from second fetch
    expect(result.current.data).toBe('second');
  });

  it('should reset to idle when fetcher changes to null', async () => {
    const fetcher = vi.fn(() => Promise.resolve('data'));

    const { result, rerender } = renderHook(
      ({ fn }) => useAsyncData(fn),
      { initialProps: { fn: fetcher as (() => Promise<string>) | null } },
    );

    await waitFor(() => expect(result.current.data).toBe('data'));

    rerender({ fn: null });

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
      expect(result.current.data).toBeNull();
      expect(result.current.error).toBeNull();
    });
  });

  it('should call fetcher only once per identity', async () => {
    const fetcher = vi.fn(() => Promise.resolve('data'));

    const { result } = renderHook(() => useAsyncData(fetcher));

    await waitFor(() => expect(result.current.data).toBe('data'));

    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it('should work with useCallback pattern', async () => {
    const spy = vi.fn((id: number) => Promise.resolve(`item-${id}`));

    const { result, rerender } = renderHook(
      ({ id }) => {
        const fetchFn = useCallback(() => spy(id), [id]);
        return useAsyncData(fetchFn);
      },
      { initialProps: { id: 1 } },
    );

    await waitFor(() => expect(result.current.data).toBe('item-1'));

    rerender({ id: 2 });

    await waitFor(() => expect(result.current.data).toBe('item-2'));
    expect(spy).toHaveBeenCalledTimes(2);
  });

  it('clears previous data immediately when navigating to another resource', async () => {
    const first = () => Promise.resolve('first');
    const pending = deferred<string>();
    const second = () => pending.promise;
    const { result, rerender } = renderHook(({ fn }) => useAsyncData(fn), { initialProps: { fn: first } });
    await waitFor(() => expect(result.current.data).toBe('first'));

    rerender({ fn: second });
    expect(result.current).toEqual({ data: null, loading: true, error: null, retry: expect.any(Function) });
    await act(async () => pending.resolve('second'));
    expect(result.current.data).toBe('second');
  });

  it('does not reuse old data when reactivating the same fetcher after idle', async () => {
    const pending = deferred<string>();
    const fetcher = vi.fn().mockResolvedValueOnce('first').mockReturnValueOnce(pending.promise);
    const { result, rerender } = renderHook(({ fn }) => useAsyncData(fn), {
      initialProps: { fn: fetcher as (() => Promise<string>) | null },
    });
    await waitFor(() => expect(result.current.data).toBe('first'));

    rerender({ fn: null });
    expect(result.current).toEqual({ data: null, loading: false, error: null, retry: expect.any(Function) });
    rerender({ fn: fetcher });
    expect(result.current).toEqual({ data: null, loading: true, error: null, retry: expect.any(Function) });
    await act(async () => pending.resolve('fresh'));
    expect(result.current.data).toBe('fresh');
  });

  it('reports synchronous failures through the same error state as rejected promises', async () => {
    const fetcher = vi.fn((): Promise<string> => { throw new Error('Invalid request'); });
    const { result } = renderHook(() => useAsyncData(fetcher));
    await waitFor(() => expect(result.current.error).toBe('Invalid request'));
    expect(result.current.loading).toBe(false);
  });

  it('uses the shared error formatter for API errors', async () => {
    const fetcher = () => Promise.reject(new ApiError('Unavailable', 503, 'Service Unavailable'));
    const { result } = renderHook(() => useAsyncData(fetcher));
    await waitFor(() => expect(result.current.error).toBe('Unavailable (503)'));
  });

  it('aborts the previous signal and ignores its late rejection', async () => {
    const pending = deferred<string>();
    const first = vi.fn<(signal: AbortSignal) => Promise<string>>().mockReturnValue(pending.promise);
    const second = vi.fn<(signal: AbortSignal) => Promise<string>>().mockResolvedValue('second');
    const { result, rerender } = renderHook(({ fn }) => useAsyncData(fn), { initialProps: { fn: first } });

    rerender({ fn: second });
    expect(first.mock.calls[0][0].aborted).toBe(true);
    expect(second.mock.calls[0][0].aborted).toBe(false);
    await waitFor(() => expect(result.current.data).toBe('second'));
    await act(async () => pending.reject(new Error('late error')));
    expect(result.current).toEqual({ data: 'second', loading: false, error: null, retry: expect.any(Function) });
  });

  it.each(['resolve', 'reject'] as const)('aborts on unmount and ignores a late %s', async (settle) => {
    const pending = deferred<string>();
    const fetcher = vi.fn<(signal: AbortSignal) => Promise<string>>().mockReturnValue(pending.promise);
    const { result, unmount } = renderHook(() => useAsyncData(fetcher));
    unmount();
    expect(fetcher.mock.calls[0][0].aborted).toBe(true);

    await act(async () => pending[settle]('late'));
    expect(result.current).toEqual({ data: null, loading: true, error: null, retry: expect.any(Function) });
  });
});
