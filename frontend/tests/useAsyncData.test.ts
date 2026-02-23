import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor, act } from '@testing-library/react';
import { useAsyncData } from '../src/utils/useAsyncData';
import { useCallback } from 'react';

describe('useAsyncData', () => {
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
});
