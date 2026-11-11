import { act, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { useItems } from '../../src/data/items/useItems';
import { ApiError } from '../../src/api/transport';
import type { ItemGateway } from '../../src/data/contracts';
import type { GetItemsResult } from '../../src/api/items';
import { createMockItem } from '../testUtils/factories';
import { deferred } from '../testUtils/deferred';

const first = createMockItem({ id: 1, categoryId: 1 });
const second = createMockItem({ id: 2, categoryId: 2 });
const response = (items = [first], etag: string | null = 'v1'): GetItemsResult => ({ items, etag, notModified: false });
function setup() {
  const api = { getAll: vi.fn().mockResolvedValue(response()), getById: vi.fn().mockResolvedValue(first),
    create: vi.fn().mockResolvedValue(second), update: vi.fn(), delete: vi.fn() } satisfies ItemGateway;
  const sync = vi.fn().mockResolvedValue(undefined);
  return { api, sync, ...renderHook(() => useItems(api, sync)) };
}

describe('items module', () => {
  afterEach(() => vi.restoreAllMocks());

  it('keeps a stable loader and revalidates cached items using their ETag', async () => {
    const { result, api } = setup();
    const load = result.current.loadItemsForCategory;
    await act(async () => { await load(1); });
    expect(result.current.loadItemsForCategory).toBe(load);
    expect(result.current.items).toEqual([first]);
    expect(api.getAll).toHaveBeenCalledWith({ categoryId: 1, includeDescendants: true, etag: undefined }, undefined);
    const pending = deferred<GetItemsResult>();
    api.getAll.mockReturnValueOnce(pending.promise);
    let request!: Promise<void>;
    act(() => { request = result.current.loadItemsForCategory(1); });
    expect(result.current.items).toEqual([first]);
    expect(result.current.itemsLoading).toBe(true);
    expect(api.getAll).toHaveBeenLastCalledWith({ categoryId: 1, includeDescendants: true, etag: 'v1' }, undefined);
    await act(async () => { pending.resolve({ items: [], etag: null, notModified: true }); await request; });
    expect(result.current.items).toEqual([first]);
    expect(result.current.itemsLoading).toBe(false);
  });

  it('handles missing ETags and rejects an unsolicited not-modified response', async () => {
    const { result, api } = setup();
    api.getAll.mockResolvedValue(response([first], null));
    await act(async () => { await result.current.loadItemsForCategory(1); });
    await act(async () => { await result.current.loadItemsForCategory(1); });
    expect(api.getAll).toHaveBeenLastCalledWith({ categoryId: 1, includeDescendants: true, etag: undefined }, undefined);
    api.getAll.mockResolvedValue({ items: [], etag: null, notModified: true });
    await act(async () => { await result.current.loadItemsForCategory(2); });
    expect(result.current.itemsError).toBe('Received unchanged items without a cached response');
    expect(result.current.items).toEqual([]);
  });

  it.each(['success', 'failure'])('ignores a late %s after a category change', async outcome => {
    const { result, api } = setup();
    const old = deferred<GetItemsResult>();
    const current = deferred<GetItemsResult>();
    api.getAll.mockReturnValueOnce(old.promise).mockReturnValueOnce(current.promise);
    let oldRequest!: Promise<void>;
    let currentRequest!: Promise<void>;
    act(() => { oldRequest = result.current.loadItemsForCategory(1); });
    act(() => { currentRequest = result.current.loadItemsForCategory(2); });
    await act(async () => {
      if (outcome === 'success') old.resolve(response()); else old.reject(new Error('Old failure'));
      await oldRequest;
    });
    expect(result.current.items).toEqual([]);
    expect(result.current.itemsError).toBeNull();
    expect(result.current.itemsLoading).toBe(true);
    await act(async () => { current.resolve(response([second])); await currentRequest; });
    expect(result.current.items).toEqual([second]);
    expect(result.current.itemsLoading).toBe(false);
  });

  it('reports the active failure and clears it on retry', async () => {
    const { result, api } = setup();
    api.getAll.mockRejectedValueOnce('unknown');
    await act(async () => { await result.current.loadItemsForCategory(1); });
    expect(result.current.itemsError).toBe('Failed to fetch items');
    await act(async () => { await result.current.loadItemsForCategory(1); });
    expect(result.current.itemsError).toBeNull();
  });

  it('retries an invalidated in-flight response before publishing or caching its membership', async () => {
    const { result, api } = setup();
    const pending = deferred<GetItemsResult>();
    api.getAll.mockReturnValueOnce(pending.promise);
    let request!: Promise<void>;
    act(() => { request = result.current.loadItemsForCategory(1); });
    act(() => result.current.invalidateItemCache());
    api.getAll.mockResolvedValue(response([second], 'fresh'));
    await act(async () => { pending.resolve(response()); await request; });
    expect(result.current.items).toEqual([second]);
    expect(result.current.itemsLoading).toBe(false);
    expect(api.getAll).toHaveBeenCalledTimes(2);
    expect(api.getAll).toHaveBeenLastCalledWith({ categoryId: 1, includeDescendants: true, etag: undefined }, undefined);
    await act(async () => { await result.current.loadItemsForCategory(1); });
    expect(api.getAll).toHaveBeenLastCalledWith({ categoryId: 1, includeDescendants: true, etag: 'fresh' }, undefined);
  });

  it('invalidates pending loads on unmount', async () => {
    const { result, api, unmount } = setup();
    const pending = deferred<GetItemsResult>();
    api.getAll.mockReturnValueOnce(pending.promise);
    let request!: Promise<void>;
    act(() => { request = result.current.loadItemsForCategory(1); });
    unmount();
    await act(async () => { pending.resolve(response()); await request; });
    expect(result.current.items).toEqual([]);
  });

  it('loads deep-linked records without adding category membership and handles unavailable items', async () => {
    const { result, api } = setup();
    await act(async () => { expect(await result.current.loadItemById(1)).toBe(first); });
    await act(async () => { await result.current.loadItemById(1); });
    expect(result.current.items).toEqual([]);
    expect(result.current.itemDetails.size).toBe(1);
    expect(result.current.itemDetails.get(1)).toBe(first);
    api.getById.mockRejectedValueOnce(new ApiError('Not found', 404, 'Not Found'));
    await act(async () => { expect(await result.current.loadItemById(99)).toBeNull(); });
    expect(result.current.items).toEqual([]);
    expect(result.current.itemDetails.get(99)).toBeNull();
  });

  it('maintains items and invalidates cached lists after mutations', async () => {
    const { result, api, sync } = setup();
    await act(async () => { await result.current.loadItemsForCategory(1); });
    api.getAll.mockResolvedValue(response([first, second]));
    await act(async () => { expect(await result.current.addItem(second)).toBe(2); });
    const updated = { ...first, name: 'Edited' };
    api.update.mockResolvedValue(updated);
    api.getAll.mockResolvedValue(response([updated, second]));
    await act(async () => { await result.current.updateItem(1, { name: 'Edited' }); });
    expect(api.update).toHaveBeenCalledWith(1, updated);
    expect(result.current.items).toEqual([updated, second]);
    expect(result.current.itemDetails.get(1)).toBe(updated);
    expect(result.current.itemDetails.get(2)).toBe(second);
    expect(api.update).toHaveBeenCalledTimes(1);
    api.getAll.mockResolvedValue(response([second]));
    await act(async () => { await result.current.deleteItem(1); });
    expect(result.current.items).toEqual([second]);
    expect(result.current.itemDetails.get(1)).toBeNull();
    expect(sync).toHaveBeenCalledTimes(3);
    await act(async () => { await result.current.deleteItem(99); });
    expect(sync).toHaveBeenCalledTimes(3);
    expect(api.getAll).toHaveBeenLastCalledWith({ categoryId: 1, includeDescendants: true, etag: undefined }, { signal: undefined });
  });

  it('leaves local state intact when a mutation fails', async () => {
    const { result, api, sync } = setup();
    await act(async () => { await result.current.loadItemsForCategory(1); });
    api.delete.mockRejectedValueOnce(new Error('Cannot delete'));
    await act(async () => { await expect(result.current.deleteItem(1)).rejects.toThrow('Cannot delete'); });
    expect(result.current.items).toEqual([first]);
    expect(sync).not.toHaveBeenCalled();
  });

  it('fetches and updates an item that is absent from the category cache', async () => {
    const { result, api, sync } = setup();
    const updated = { ...first, name: 'Saved from a deep link' };
    api.update.mockResolvedValue(updated);
    await act(async () => {
      expect(await result.current.updateItem(1, { name: updated.name })).toEqual(updated);
    });
    expect(api.getById).toHaveBeenCalledWith(1);
    expect(api.update).toHaveBeenCalledWith(1, updated);
    expect(result.current.items).toEqual([]);
    expect(result.current.itemDetails.get(1)).toBe(updated);
    expect(sync).toHaveBeenCalledWith(first.collectionId);
  });

  it.each([new Error('Offline'), new ApiError('Server unavailable', 500, 'Internal Server Error')])('preserves recoverable fetch failures: %s', async error => {
    const { result, api } = setup();
    api.getById.mockRejectedValue(error);
    await expect(result.current.loadItemById(1)).rejects.toBe(error);
    expect(result.current.items).toEqual([]);
  });

  it.each(['aborted', 'invalidated'])('does not cache a detail response after its request is %s', async reason => {
    const { result, api } = setup();
    const pending = deferred<typeof first>();
    const controller = new AbortController();
    api.getById.mockReturnValueOnce(pending.promise);
    let request!: Promise<unknown>;
    act(() => { request = result.current.loadItemById(1, { signal: controller.signal }); });
    if (reason === 'aborted') controller.abort(); else act(() => result.current.invalidateItemCache());
    await act(async () => { pending.resolve(first); await request; });
    expect(api.getById).toHaveBeenCalledWith(1, { signal: controller.signal });
    expect(result.current.items).toEqual([]);
  });

  it('passes fetch failures through when an uncached item cannot be updated', async () => {
    const { result, api, sync } = setup();
    api.getById.mockRejectedValue(new Error('Item unavailable'));
    await expect(result.current.updateItem(1, { name: 'Draft' })).rejects.toThrow('Item unavailable');
    expect(api.update).not.toHaveBeenCalled();
    expect(sync).not.toHaveBeenCalled();
  });
});

it('refreshes the active category with a new cache generation and propagates required failures', async () => {
  const { result, api } = setup();
  const options = { signal: new AbortController().signal, throwOnError: true };
  await act(async () => { await result.current.refreshLoadedItems(options); });
  expect(api.getAll).not.toHaveBeenCalled();
  await act(async () => { await result.current.loadItemsForCategory(1); });
  const fresh = { ...first, effectiveIsPublic: true, name: 'Published' };
  api.getAll.mockResolvedValue(response([fresh]));
  await act(async () => { await result.current.refreshLoadedItems(options); });
  expect(api.getAll).toHaveBeenLastCalledWith({ categoryId: 1, includeDescendants: true, etag: undefined }, options);
  expect(result.current.items).toEqual([fresh]);
  api.getAll.mockRejectedValueOnce(new Error('Refresh failed'));
  await act(async () => { await expect(result.current.refreshLoadedItems(options)).rejects.toThrow('Refresh failed'); });
  expect(result.current.itemsError).toBe('Refresh failed');
});

it('replaces a refreshed detail, preserves other loaded items, and reports a missing detail', async () => {
  const { result, api } = setup();
  const options = { signal: new AbortController().signal, throwOnError: true };
  api.getAll.mockResolvedValue(response([first, second]));
  await act(async () => { await result.current.loadItemsForCategory(1); await result.current.loadItemById(1); });
  const fresh = { ...first, effectiveIsPublic: true };
  api.getById.mockResolvedValue(fresh);
  await act(async () => { await result.current.refreshLoadedItems(options); });
  expect(api.getById).toHaveBeenLastCalledWith(1, options);
  expect(result.current.items).toEqual([fresh, second]);
  api.getById.mockRejectedValueOnce(new ApiError('Not found', 404, 'Not Found'));
  await act(async () => { await expect(result.current.refreshLoadedItems(options)).rejects.toThrow('no longer available'); });
  expect(result.current.items).toEqual([second]);
  expect(result.current.itemDetails.get(1)).toBeNull();
});

it.each(['item', 'missing'] as const)('ignores an older %s response for an item after a newer read succeeds', async outcome => {
  const { result, api } = setup();
  const pending = deferred<typeof first>();
  api.getById.mockReturnValueOnce(pending.promise);
  let old!: Promise<unknown>;
  act(() => { old = result.current.loadItemById(1); });
  const current = { ...first, name: 'Latest' };
  api.getById.mockResolvedValueOnce(current);
  await act(async () => { await result.current.loadItemById(1); });
  await act(async () => {
    if (outcome === 'item') pending.resolve(first);
    else pending.reject(new ApiError('Gone', 404, 'Not Found'));
    await old;
  });
  expect(result.current.items).toEqual([]);
  expect(result.current.itemDetails.get(1)).toBe(current);
});

it('prevents an older list from restoring an item that a later detail request found missing', async () => {
  const { result, api } = setup();
  const pending = deferred<GetItemsResult>();
  api.getAll.mockReturnValueOnce(pending.promise);
  let list!: Promise<void>;
  act(() => { list = result.current.loadItemsForCategory(1); });
  api.getById.mockRejectedValueOnce(new ApiError('Gone', 404, 'Not Found'));
  await act(async () => { await result.current.loadItemById(1); });
  await act(async () => { pending.resolve(response([first, second])); await list; });
  expect(result.current.items).toEqual([second]);
  expect(result.current.itemDetails.get(1)).toBeNull();
  const revalidate = deferred<GetItemsResult>();
  api.getAll.mockReturnValueOnce(revalidate.promise);
  act(() => { list = result.current.loadItemsForCategory(1); });
  expect(result.current.items).toEqual([second]);
  await act(async () => { revalidate.resolve({ items: [], etag: null, notModified: true }); await list; });
  expect(result.current.items).toEqual([second]);
  expect(result.current.itemDetails.get(1)).toBeNull();
});

it('does not replace refreshed details with old cached payloads when the list returns 304', async () => {
  const { result, api } = setup();
  await act(async () => { await result.current.loadItemsForCategory(1); });
  const pending = deferred<GetItemsResult>();
  api.getAll.mockReturnValueOnce(pending.promise);
  let list!: Promise<void>;
  act(() => { list = result.current.loadItemsForCategory(1); });
  const fresh = { ...first, name: 'Fresh detail' };
  api.getById.mockResolvedValueOnce(fresh);
  await act(async () => { await result.current.loadItemById(1); });
  await act(async () => { pending.resolve(response()); await list; });
  api.getAll.mockResolvedValueOnce({ items: [], etag: null, notModified: true });
  await act(async () => { await result.current.loadItemsForCategory(1); });
  expect(result.current.items).toEqual([fresh]);
  expect(result.current.itemDetails.get(1)).toBe(fresh);
});

it('rejects a pre-aborted detail read without contacting the gateway', async () => {
  const { result, api } = setup();
  const controller = new AbortController();
  controller.abort();
  await expect(result.current.loadItemById(1, { signal: controller.signal })).rejects.toMatchObject({ name: 'AbortError' });
  expect(api.getById).not.toHaveBeenCalled();
});

it('does not erase a record when an aborted read later reports 404', async () => {
  const { result, api } = setup();
  await act(async () => { await result.current.loadItemById(1); });
  const pending = deferred<typeof first>();
  api.getById.mockReturnValueOnce(pending.promise);
  const controller = new AbortController();
  let request!: Promise<unknown>;
  act(() => { request = result.current.loadItemById(1, { signal: controller.signal }); });
  controller.abort();
  await act(async () => { pending.reject(new ApiError('Gone', 404, 'Not Found')); await request; });
  expect(result.current.itemDetails.get(1)).toBe(first);
});

it.each(['create', 'update', 'delete'] as const)('does not publish or synchronize a completed %s after the workspace unmounts', async operation => {
  const { result, api, sync, unmount } = setup();
  await act(async () => { await result.current.loadItemById(1); });
  const pending = deferred<typeof first>();
  api.create.mockReturnValueOnce(pending.promise);
  api.update.mockReturnValueOnce(pending.promise);
  api.delete.mockImplementationOnce(async () => { await pending.promise; });
  let request!: Promise<unknown>;
  act(() => { request = operation === 'create' ? result.current.addItem(first)
    : operation === 'update' ? result.current.updateItem(1, { name: 'Saved' }) : result.current.deleteItem(1); });
  const previous = result.current.itemDetails;
  unmount();
  await act(async () => { pending.resolve({ ...first, name: 'Saved' }); await request; });
  expect(result.current.itemDetails).toBe(previous);
  expect(sync).not.toHaveBeenCalled();
});

it('does not start a write if an uncached-item lookup finishes after leaving the workspace', async () => {
  const { result, api, sync, unmount } = setup();
  const pending = deferred<typeof first>();
  api.getById.mockReturnValueOnce(pending.promise);
  const request = result.current.updateItem(1, { name: 'Saved' });
  unmount();
  pending.resolve(first);
  await expect(request).rejects.toMatchObject({ name: 'AbortError' });
  expect(api.update).not.toHaveBeenCalled();
  expect(sync).not.toHaveBeenCalled();
});

it.each(['before', 'during'])('aborts a required list refresh %s fetching without publishing an error', async timing => {
  const { result, api } = setup();
  const controller = new AbortController();
  const pending = deferred<GetItemsResult>();
  api.getAll.mockReturnValueOnce(pending.promise);
  if (timing === 'before') controller.abort();
  let request!: Promise<void>;
  act(() => { request = result.current.loadItemsForCategory(1, { signal: controller.signal, throwOnError: true }); });
  controller.abort();
  await act(async () => {
    pending.resolve(response());
    await expect(request).rejects.toMatchObject({ name: 'AbortError' });
  });
  expect(result.current.items).toEqual([]);
  expect(result.current.itemsError).toBeNull();
  expect(result.current.itemsLoading).toBe(false);
  expect(api.getAll).toHaveBeenCalledTimes(timing === 'before' ? 0 : 1);
});
