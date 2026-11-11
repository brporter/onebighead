import { StrictMode } from 'react';
import { act, renderHook, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { useItemDetails } from '../../src/data/items/useItemDetails';
import { useItems } from '../../src/data/items/useItems';
import { ApiError } from '../../src/api/transport';
import type { ItemGateway } from '../../src/data/contracts';
import type { GetItemsResult } from '../../src/api/items';
import type { Item } from '../../src/utils/types';
import { createMockItem } from '../testUtils/factories';
import { deferred } from '../testUtils/deferred';

const first = createMockItem();
const second = createMockItem({ id: 2 });
function setup() {
  const api = { getAll: vi.fn().mockResolvedValue({ items: [], etag: null, notModified: false }),
    getById: vi.fn().mockResolvedValue(first), create: vi.fn(), update: vi.fn(), delete: vi.fn() } satisfies ItemGateway;
  const sync = vi.fn().mockResolvedValue(undefined);
  const record = vi.fn().mockResolvedValue(undefined);
  return { api, record, ...renderHook(({ collectionId, itemId }) => {
    const data = useItems(api, sync);
    return { data, ...useItemDetails(collectionId, itemId, data, record) };
  }, { initialProps: { collectionId: 1, itemId: 1 }, wrapper: StrictMode }) };
}

it('keeps an open detail during category loading and follows later cache updates without duplicate views', async () => {
  const { result, api, record } = setup();
  await waitFor(() => expect(result.current.item).toBe(first));
  const pending = deferred<GetItemsResult>();
  api.getAll.mockReturnValueOnce(pending.promise);
  let request!: Promise<void>;
  act(() => { request = result.current.data.loadItemsForCategory(2); });
  expect(result.current.data.items).toEqual([]);
  expect(result.current.item).toBe(first);
  expect(result.current.loading).toBe(false);
  await act(async () => { pending.resolve({ items: [second], etag: null, notModified: false }); await request; });
  expect(result.current.item).toBe(first);
  const fresh = { ...first, name: 'Published', effectiveIsPublic: true };
  api.getById.mockResolvedValue(fresh);
  await act(async () => { await result.current.data.loadItemById(1); });
  expect(result.current.item).toBe(fresh);
  expect(record).toHaveBeenCalledExactlyOnceWith(1);
});

it('fetches deep links independently of categories and does not reload on unrelated renders', async () => {
  const { result, rerender, api, record } = setup();
  await waitFor(() => expect(result.current.item).toBe(first));
  const count = api.getById.mock.calls.length;
  rerender({ collectionId: 1, itemId: 1 });
  expect(api.getById).toHaveBeenCalledTimes(count);
  expect(api.getById).toHaveBeenLastCalledWith(1, { signal: expect.any(AbortSignal) });
  expect(api.getAll).not.toHaveBeenCalled();
  expect(record).toHaveBeenCalledExactlyOnceWith(1);
});

it('clears old details immediately on navigation and rejects the wrong collection', async () => {
  const { result, rerender, api, record } = setup();
  await waitFor(() => expect(result.current.item).toBe(first));
  const pending = deferred<Item>();
  api.getById.mockReturnValueOnce(pending.promise);
  rerender({ collectionId: 1, itemId: 2 });
  expect(result.current.item).toBeNull();
  expect(result.current.loading).toBe(true);
  await act(async () => pending.resolve(second));
  expect(result.current.item).toBe(second);
  rerender({ collectionId: 99, itemId: 2 });
  expect(result.current.item).toBeNull();
  expect(record).toHaveBeenCalledTimes(2);
});

it('rejects a response with the wrong item ID', async () => {
  const { result, rerender, api } = setup();
  await waitFor(() => expect(result.current.item).toBe(first));
  api.getById.mockResolvedValue(first);
  rerender({ collectionId: 1, itemId: 99 });
  await waitFor(() => expect(result.current.loading).toBe(false));
  expect(result.current.item).toBeNull();
  expect(result.current.data.itemDetails.get(99)).toBeNull();
});

it('clears a cached item after a confirmed 404 and allows a later retry to recover', async () => {
  const { result, api, record } = setup();
  await waitFor(() => expect(result.current.item).toBe(first));
  const pending = deferred<Item>();
  api.getById.mockReturnValueOnce(pending.promise);
  act(() => result.current.retry());
  expect(result.current.item).toBe(first);
  await act(async () => pending.reject(new ApiError('Gone', 404, 'Not Found')));
  expect(result.current.item).toBeNull();
  expect(result.current.loading).toBe(false);
  expect(result.current.error).toBeNull();
  expect(result.current.data.items).toEqual([]);
  act(() => result.current.retry());
  await waitFor(() => expect(result.current.item).toBe(first));
  expect(record).toHaveBeenCalledExactlyOnceWith(1);
});

it('reports recoverable failures, preserves cached data for a retry, and tolerates view tracking failure', async () => {
  const { result, rerender, api, record } = setup();
  await waitFor(() => expect(result.current.item).toBe(first));
  api.getById.mockRejectedValueOnce(new Error('Offline'));
  act(() => result.current.retry());
  await waitFor(() => expect(result.current.error).toBe('Offline'));
  expect(result.current.item).toBe(first);
  api.getById.mockResolvedValue(second);
  record.mockRejectedValue(new Error('Tracking unavailable'));
  rerender({ collectionId: 1, itemId: 2 });
  await waitFor(() => expect(result.current.item).toBe(second));
  expect(result.current.error).toBeNull();
});

it('aborts abandoned requests and prevents late responses from repopulating detail records', async () => {
  const { result, rerender, api, unmount, record } = setup();
  await waitFor(() => expect(result.current.item).toBe(first));
  const pending = deferred<Item>();
  api.getById.mockReturnValueOnce(pending.promise);
  rerender({ collectionId: 1, itemId: 2 });
  const signal = api.getById.mock.calls[api.getById.mock.calls.length - 1][1].signal as AbortSignal;
  unmount();
  expect(signal.aborted).toBe(true);
  await act(async () => pending.resolve(second));
  expect(result.current.item).toBeNull();
  expect(result.current.data.itemDetails.has(2)).toBe(false);
  expect(record).toHaveBeenCalledExactlyOnceWith(1);
});

it('removes a displayed item when it is deleted through the data module', async () => {
  const { result } = setup();
  await waitFor(() => expect(result.current.item).toBe(first));
  await act(async () => { await result.current.data.deleteItem(1); });
  expect(result.current.item).toBeNull();
});
