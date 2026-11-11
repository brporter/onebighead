import { act, renderHook } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { useItems } from '../../src/data/items/useItems';
import { useCategoryItems } from '../../src/data/items/useCategoryItems';
import { ItemRecords } from '../../src/data/items/ItemRecords';
import type { ItemGateway } from '../../src/data/contracts';
import type { GetItemsResult } from '../../src/api/items';
import type { Item } from '../../src/utils/types';
import { createMockItem } from '../testUtils/factories';
import { deferred } from '../testUtils/deferred';

const first = createMockItem({ id: 1, categoryId: 1, collectionId: 1 });
const other = createMockItem({ id: 2, categoryId: 2, collectionId: 2 });
const sibling = createMockItem({ id: 3, categoryId: 1, collectionId: 1 });
const saved = { ...first, name: 'Saved' };
const response = (items: Item[], etag = 'fresh'): GetItemsResult => ({ items, etag, notModified: false });
const operations = ['create', 'update', 'delete'] as const;
function setup() {
  const api = { getAll: vi.fn().mockResolvedValue(response([first, sibling])), getById: vi.fn().mockResolvedValue(first),
    create: vi.fn().mockResolvedValue(saved), update: vi.fn().mockResolvedValue(saved), delete: vi.fn() } satisfies ItemGateway;
  const sync = vi.fn().mockResolvedValue(undefined);
  return { api, sync, ...renderHook(() => useItems(api, sync)) };
}
function write(data: ReturnType<typeof useItems>, operation: typeof operations[number]) {
  if (operation === 'create') return data.addItem(saved);
  if (operation === 'update') return data.updateItem(1, { name: 'Saved' });
  return data.deleteItem(1);
}

it.each(operations)('revalidates list membership after %s overlaps the initial read, keeping unrelated rows', async operation => {
  const { api, result } = setup();
  const old = deferred<GetItemsResult>();
  const fresh = deferred<GetItemsResult>();
  api.getAll.mockReturnValueOnce(old.promise).mockReturnValueOnce(fresh.promise);
  let reading!: Promise<void>;
  act(() => { reading = result.current.loadItemsForCategory(1); });
  await act(async () => { await write(result.current, operation); });
  expect(result.current.itemsLoading).toBe(true);
  expect(result.current.items).toEqual([]);
  await act(async () => { old.resolve(response([first], 'obsolete')); });
  expect(result.current.itemsLoading).toBe(true);
  expect(result.current.items).toEqual([]);
  expect(api.getAll).toHaveBeenLastCalledWith({ categoryId: 1, includeDescendants: true, etag: undefined }, undefined);
  const expected = operation === 'delete' ? [sibling] : [saved, sibling];
  await act(async () => { fresh.resolve(response(expected)); await reading; });
  expect(result.current.items).toEqual(expected);
  expect(result.current.itemsLoading).toBe(false);
  expect(api[operation]).toHaveBeenCalledTimes(1);
});

it.each(operations)('does not insert a late %s from another collection or cancel the active collection read', async operation => {
  const { api, result } = setup();
  await act(async () => { await result.current.loadItemsForCategory(1); });
  const mutation = deferred<unknown>();
  const old = deferred<GetItemsResult>();
  const fresh = deferred<GetItemsResult>();
  api[operation].mockReturnValueOnce(mutation.promise);
  api.getAll.mockReturnValueOnce(old.promise).mockReturnValueOnce(fresh.promise);
  let writing!: Promise<unknown>;
  let reading!: Promise<void>;
  act(() => { writing = write(result.current, operation); reading = result.current.loadItemsForCategory(2); });
  await act(async () => { mutation.resolve(operation === 'delete' ? undefined : saved); await writing; });
  expect(result.current.items).toEqual([]);
  expect(result.current.itemsLoading).toBe(true);
  await act(async () => { old.resolve(response([other], 'obsolete')); });
  expect(result.current.itemsLoading).toBe(true);
  expect(api.getAll).toHaveBeenLastCalledWith({ categoryId: 2, includeDescendants: true, etag: undefined }, undefined);
  await act(async () => { fresh.resolve(response([other])); await reading; });
  expect(result.current.items).toEqual([other]);
  expect(result.current.itemDetails.get(1)).toEqual(operation === 'delete' ? null : saved);
});

it('does not duplicate a creation already returned by a list read', async () => {
  const { api, result } = setup();
  const pending = deferred<Item>();
  api.create.mockReturnValueOnce(pending.promise);
  api.getAll.mockResolvedValue(response([saved, sibling]));
  let writing!: Promise<number>;
  act(() => { writing = result.current.addItem(saved); });
  await act(async () => { await result.current.loadItemsForCategory(1); });
  await act(async () => { pending.resolve(saved); await writing; });
  expect(result.current.items).toEqual([saved, sibling]);
  expect(api.create).toHaveBeenCalledOnce();
});

it('keeps detail responses outside an unrelated category list, including when they finish last', async () => {
  const { api, result } = setup();
  const pending = deferred<Item>();
  api.getById.mockReturnValueOnce(pending.promise);
  let detail!: Promise<Item | null>;
  act(() => { detail = result.current.loadItemById(1); });
  api.getAll.mockResolvedValue(response([other]));
  await act(async () => { await result.current.loadItemsForCategory(2); });
  await act(async () => { pending.resolve(first); await detail; });
  expect(result.current.items).toEqual([other]);
  expect(result.current.itemDetails.get(1)).toBe(first);
});

it('uses the server to resolve membership after an item moves outside the selected category subtree', async () => {
  const { api, result } = setup();
  await act(async () => { await result.current.loadItemsForCategory(1); });
  const moved = { ...first, categoryId: 5 };
  api.update.mockResolvedValue(moved);
  api.getAll.mockResolvedValue(response([sibling]));
  await act(async () => { await result.current.updateItem(1, { categoryId: 5 }); });
  expect(result.current.items).toEqual([sibling]);
  expect(result.current.itemDetails.get(1)).toBe(moved);
});

it('coalesces invalidations during a pending read and retries its obsolete failure without showing an error', async () => {
  const { api, result } = setup();
  const pending = deferred<GetItemsResult>();
  api.getAll.mockReturnValueOnce(pending.promise).mockResolvedValue(response([saved, sibling]));
  let reading!: Promise<void>;
  act(() => { reading = result.current.loadItemsForCategory(1); });
  act(() => { result.current.invalidateItemCache(); result.current.invalidateItemCache(); });
  await act(async () => { pending.reject(new Error('Old request failed')); await reading; });
  expect(api.getAll).toHaveBeenCalledTimes(2);
  expect(result.current.itemsError).toBeNull();
  expect(result.current.items).toEqual([saved, sibling]);
});

it('preserves a confirmed edit when background revalidation fails and retries only the read', async () => {
  const { api, result, sync } = setup();
  await act(async () => { await result.current.loadItemsForCategory(1); });
  api.getAll.mockRejectedValueOnce(new Error('Refresh unavailable'));
  await act(async () => { expect(await result.current.updateItem(1, { name: 'Saved' })).toBe(saved); });
  expect(result.current.items).toEqual([saved, sibling]);
  expect(result.current.itemsError).toBe('Refresh unavailable');
  expect(sync).toHaveBeenCalledWith(1);
  api.getAll.mockResolvedValue(response([saved, sibling]));
  await act(async () => { await result.current.loadItemsForCategory(1); });
  expect(result.current.itemsError).toBeNull();
  expect(api.update).toHaveBeenCalledOnce();
});

it('propagates a required refresh failure after an obsolete response is discarded', async () => {
  const { api, result } = setup();
  const pending = deferred<GetItemsResult>();
  const error = new Error('Retry failed');
  api.getAll.mockReturnValueOnce(pending.promise).mockRejectedValueOnce(error);
  let reading!: Promise<void>;
  act(() => { reading = result.current.loadItemsForCategory(1, { throwOnError: true }); });
  act(() => { result.current.invalidateItemCache(); });
  await act(async () => { pending.resolve(response([first])); await expect(reading).rejects.toBe(error); });
  expect(result.current.items).toEqual([]);
  expect(result.current.itemsError).toBe(error.message);
});

it('does not revalidate an abandoned category or start reads from retired callbacks', async () => {
  const { api, result, unmount } = setup();
  const controller = new AbortController();
  await act(async () => { await result.current.loadItemsForCategory(1, { signal: controller.signal }); });
  controller.abort();
  act(() => { result.current.invalidateItemCache(); });
  expect(api.getAll).toHaveBeenCalledOnce();
  unmount();
  await act(async () => { result.current.invalidateItemCache(); await result.current.loadItemsForCategory(2); });
  await expect(result.current.loadItemById(1)).rejects.toMatchObject({ name: 'AbortError' });
  expect(api.getAll).toHaveBeenCalledOnce();
  expect(api.getById).not.toHaveBeenCalled();
});

it('does not schedule a list refresh before selection or after its owner unmounts', async () => {
  const gateway = { getAll: vi.fn() };
  const records = new ItemRecords();
  const { result, unmount } = renderHook(() => useCategoryItems(gateway, records));
  act(() => { result.current.invalidate(true); });
  unmount();
  act(() => { result.current.invalidate(true); });
  expect(gateway.getAll).not.toHaveBeenCalled();
});

it.each(['resolve', 'reject'] as const)('does not retry an invalidated request that later %ss after abort', async outcome => {
  const { api, result } = setup();
  const pending = deferred<GetItemsResult>();
  const controller = new AbortController();
  api.getAll.mockReturnValueOnce(pending.promise);
  let reading!: Promise<void>;
  act(() => { reading = result.current.loadItemsForCategory(1, { signal: controller.signal }); });
  act(() => { result.current.invalidateItemCache(); });
  controller.abort();
  await act(async () => {
    if (outcome === 'resolve') pending.resolve(response([first])); else pending.reject(new Error('Aborted'));
    await reading;
  });
  expect(api.getAll).toHaveBeenCalledOnce();
  expect(result.current.itemsError).toBeNull();
  expect(result.current.itemsLoading).toBe(false);
});
