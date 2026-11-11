import { act, renderHook } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { LruCache } from '../../src/data/shared/LruCache';
import { useAsyncResource } from '../../src/data/shared/useAsyncResource';
import { deferred } from '../testUtils/deferred';
import { upsertBy } from '../../src/data/shared/upsertBy';

describe('LruCache', () => {
  it.each([0, -1, 1.5, Infinity, NaN])('rejects invalid capacity %s', capacity => {
    expect(() => new LruCache(capacity)).toThrow(RangeError);
  });
  it('evicts the least recently used entry, including reads and replacements', () => {
    const cache = new LruCache<number, string>(2);
    expect(cache.get(1)).toBeUndefined();
    cache.set(1, 'one');
    cache.set(2, 'two');
    expect(cache.get(1)).toBe('one');
    cache.set(3, 'three');
    expect(cache.get(2)).toBeUndefined();
    cache.set(1, 'updated');
    cache.set(4, 'four');
    expect(cache.get(3)).toBeUndefined();
    expect(cache.get(1)).toBe('updated');
    cache.clear();
    expect(cache.get(4)).toBeUndefined();
  });
  it('treats undefined as a stored value for access ordering', () => {
    const cache = new LruCache<string, undefined>(2);
    cache.set('a', undefined);
    cache.set('b', undefined);
    expect(cache.get('a')).toBeUndefined();
    cache.set('c', undefined);
    // A subsequently replaced value still occupies just one slot.
    cache.set('a', undefined);
    expect(cache.get('missing')).toBeUndefined();
  });
});

it('reconciles confirmed changes with an older read without losing unrelated records or duplicating a created record', async () => {
  const old = deferred<Array<{ id: number; name: string }>>();
  const { result } = renderHook(() => useAsyncResource<Array<{ id: number; name: string }>>([], 'Read failed'));
  const accepted = vi.fn();
  let read!: Promise<void>;
  act(() => { read = result.current.load(() => old.promise, {}, accepted); });
  const updated = { id: 1, name: 'Saved edit' };
  const created = { id: 3, name: 'Created' };
  act(() => {
    result.current.mutate(rows => upsertBy(rows, updated, 'id'));
    result.current.mutate(rows => rows.filter(row => row.id !== 2));
    result.current.mutate(rows => upsertBy(rows, created, 'id'));
  });
  expect(result.current.data).toEqual([updated, created]);
  const unrelated = { id: 4, name: 'Unrelated' };
  await act(async () => {
    old.resolve([{ id: 1, name: 'Old edit' }, { id: 2, name: 'Deleted' }, created, unrelated]);
    await read;
  });
  expect(result.current.data).toEqual([updated, created, unrelated]);
  expect(accepted).toHaveBeenCalledExactlyOnceWith([updated, created, unrelated]);
  expect(result.current.loading).toBe(false);
});

it('does not replay changes made before a newer read or let an older completion clear the newer read’s changes', async () => {
  const first = deferred<string[]>();
  const second = deferred<string[]>();
  const { result } = renderHook(() => useAsyncResource<string[]>([], 'Read failed'));
  let old!: Promise<void>;
  let latest!: Promise<void>;
  act(() => { old = result.current.load(() => first.promise); });
  act(() => { result.current.mutate(() => ['Old local value']); });
  act(() => { latest = result.current.load(() => second.promise); });
  await act(async () => { first.resolve(['Obsolete read']); await old; });
  act(() => { result.current.mutate(rows => rows.filter(row => row !== 'Deleted')); });
  await act(async () => { second.resolve(['New server value', 'Deleted']); await latest; });
  expect(result.current.data).toEqual(['New server value']);
  await act(async () => { await result.current.load(() => Promise.resolve(['Next read'])); });
  expect(result.current.data).toEqual(['Next read']);
});

it.each(['error', 'abort'])('retains confirmed changes after a pending read ends with %s', async outcome => {
  const response = deferred<string[]>();
  const controller = new AbortController();
  const { result } = renderHook(() => useAsyncResource<string[]>([], 'Read failed'));
  let read!: Promise<void>;
  act(() => { read = result.current.load(() => response.promise, { signal: controller.signal }); });
  act(() => { result.current.mutate(() => ['Saved']); });
  await act(async () => {
    if (outcome === 'abort') { controller.abort(); response.resolve(['Old']); }
    else response.reject(new Error('Read failed'));
    await read;
  });
  expect(result.current.data).toEqual(['Saved']);
  expect(result.current.loading).toBe(false);
  expect(result.current.error).toBe(outcome === 'abort' ? null : 'Read failed');
});

it('retires mutation callbacks and new reads when the resource unmounts', async () => {
  const { result, unmount } = renderHook(() => useAsyncResource('Initial', 'Read failed'));
  const mutate = result.current.mutate;
  const load = result.current.load;
  unmount();
  const update = vi.fn(() => 'Late');
  expect(mutate(update)).toBe(false);
  expect(update).not.toHaveBeenCalled();
  const fetcher = vi.fn();
  const accepted = vi.fn();
  await load(fetcher, {}, accepted);
  expect(fetcher).not.toHaveBeenCalled();
  expect(accepted).not.toHaveBeenCalled();
});

describe('useAsyncResource', () => {
  it('tracks loading, success, failure, retry, and local updates', async () => {
    const { result } = renderHook(() => useAsyncResource<string[]>([], 'Could not load'));
    expect(result.current.loading).toBe(false);
    const response = deferred<string[]>();
    let request!: Promise<void>;
    act(() => { request = result.current.load(() => response.promise); });
    expect(result.current.loading).toBe(true);
    await act(async () => { response.resolve(['first']); await request; });
    expect(result.current.data).toEqual(['first']);
    expect(result.current.loading).toBe(false);
    await act(async () => { await result.current.load(() => Promise.reject(new Error('Offline'))); });
    expect(result.current.error).toBe('Offline');
    await act(async () => { await result.current.load(() => Promise.reject(null)); });
    expect(result.current.error).toBe('Could not load');
    await act(async () => { await result.current.load(() => Promise.resolve(['retry'])); });
    expect(result.current.error).toBeNull();
    act(() => result.current.setData(values => [...values, 'local']));
    expect(result.current.data).toEqual(['retry', 'local']);
  });
  it.each(['success', 'failure'])('ignores stale %s without stopping the new request', async outcome => {
    const { result } = renderHook(() => useAsyncResource([], 'Error', true));
    expect(result.current.loading).toBe(true);
    const first = deferred<never[]>();
    const second = deferred<never[]>();
    let oldRequest!: Promise<void>;
    let newRequest!: Promise<void>;
    act(() => { oldRequest = result.current.load(() => first.promise); });
    act(() => { newRequest = result.current.load(() => second.promise); });
    await act(async () => {
      if (outcome === 'success') first.resolve([]); else first.reject(new Error('Old error'));
      await oldRequest;
    });
    expect(result.current.loading).toBe(true);
    expect(result.current.error).toBeNull();
    await act(async () => { second.resolve([]); await newRequest; });
    expect(result.current.loading).toBe(false);
  });
  it('invalidates pending results on unmount', async () => {
    const { result, unmount } = renderHook(() => useAsyncResource('initial', 'Error'));
    const response = deferred<string>();
    let request!: Promise<void>;
    act(() => { request = result.current.load(() => response.promise); });
    unmount();
    await act(async () => { response.resolve('late'); await request; });
    expect(result.current.data).toBe('initial');
  });
});

it('propagates required read failures and cancels both early and late responses without publishing an error', async () => {
  const { result } = renderHook(() => useAsyncResource('initial', 'Error'));
  await act(async () => { await expect(result.current.load(() => Promise.reject(new Error('Offline')), { throwOnError: true })).rejects.toThrow('Offline'); });
  expect(result.current.error).toBe('Offline');
  const controller = new AbortController();
  controller.abort();
  const fetcher = vi.fn();
  await act(async () => { await result.current.load(fetcher, { signal: controller.signal }); });
  expect(fetcher).not.toHaveBeenCalled();
  expect(result.current.error).toBeNull();
  const pending = deferred<string>();
  const lateController = new AbortController();
  let request!: Promise<void>;
  act(() => { request = result.current.load(() => pending.promise, { signal: lateController.signal, throwOnError: true }); });
  lateController.abort();
  await act(async () => { pending.resolve('late'); await expect(request).rejects.toMatchObject({ name: 'AbortError' }); });
  expect(result.current.data).toBe('initial');
  expect(result.current.loading).toBe(false);
  expect(result.current.error).toBeNull();
});
