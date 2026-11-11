import { act, renderHook } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { useCategories } from '../../src/data/categories/useCategories';
import type { CategoryGateway } from '../../src/data/contracts';
import type { Category } from '../../src/utils/types';
import { createMockCategory } from '../testUtils/factories';
import { deferred } from '../testUtils/deferred';

type Operation = 'create' | 'update' | 'delete' | 'reorder';
const operations: Operation[] = ['create', 'update', 'delete', 'reorder'];
const first = createMockCategory({ categoryId: 1, collectionId: 1, name: 'Original' });
const saved = { ...first, name: 'Saved', sortOrder: 1 };
const other = createMockCategory({ categoryId: 2, collectionId: 2, name: 'Other collection' });
const sibling = createMockCategory({ categoryId: 3, collectionId: 1, name: 'Unrelated' });
function gateway() {
  return { getAll: vi.fn().mockResolvedValue([]), create: vi.fn(), update: vi.fn(), delete: vi.fn(), reorder: vi.fn(), getTemplates: vi.fn() } satisfies CategoryGateway;
}
function write(data: ReturnType<typeof useCategories>, operation: Operation): Promise<unknown> {
  if (operation === 'create') return data.addCategory({ collectionId: 1, name: 'Saved' });
  if (operation === 'update') return data.updateCategory(1, { name: 'Saved' });
  if (operation === 'delete') return data.deleteCategory(1);
  return data.reorderCategories([{ categoryId: 1, sortOrder: 1 }]);
}
const responseFor = (operation: Operation) => operation === 'delete' ? undefined : operation === 'reorder' ? [sibling, saved] : saved;

it.each(operations)('keeps confirmed %s results when an older read for the same collection arrives', async operation => {
  const api = gateway();
  const reading = deferred<Category[]>();
  api.getAll.mockReturnValue(reading.promise);
  api[operation].mockResolvedValue(responseFor(operation));
  const { result } = renderHook(() => useCategories(api, vi.fn()));
  let read!: Promise<void>;
  act(() => { read = result.current.loadCategoriesForCollection(1); });
  await act(async () => { await write(result.current, operation); });
  await act(async () => { reading.resolve([first, sibling]); await read; });
  expect(result.current.categories).toEqual(operation === 'delete' ? [sibling] : operation === 'reorder' ? [sibling, saved] : [saved, sibling]);
});

it.each(operations)('does not publish an old %s into another collection, including after navigating back', async operation => {
  const api = gateway();
  const writing = deferred<unknown>();
  api[operation].mockReturnValue(writing.promise);
  api.getAll.mockResolvedValueOnce([first]).mockResolvedValueOnce([other]).mockResolvedValueOnce([{ ...first, name: 'Newer view' }]);
  const invalidate = vi.fn();
  const { result } = renderHook(() => useCategories(api, invalidate));
  await act(async () => { await result.current.loadCategoriesForCollection(1); });
  let pending!: Promise<unknown>;
  act(() => { pending = write(result.current, operation); });
  await act(async () => { await result.current.loadCategoriesForCollection(2); });
  expect(result.current.categories).toEqual([other]);
  await act(async () => { await result.current.loadCategoriesForCollection(1); });
  await act(async () => { writing.resolve(responseFor(operation)); await pending; });
  expect(result.current.categories).toEqual([{ ...first, name: 'Newer view' }]);
  // The committed server change must still invalidate future item reads in this workspace.
  expect(invalidate).toHaveBeenCalledTimes(operation === 'update' || operation === 'delete' ? 1 : 0);
});

it.each(operations)('retires a pending %s when the workspace provider unmounts', async operation => {
  const api = gateway();
  const writing = deferred<unknown>();
  api[operation].mockReturnValue(writing.promise);
  api.getAll.mockResolvedValue([first]);
  const invalidate = vi.fn();
  const { result, unmount } = renderHook(() => useCategories(api, invalidate));
  await act(async () => { await result.current.loadCategoriesForCollection(1); });
  let pending!: Promise<unknown>;
  act(() => { pending = write(result.current, operation); });
  unmount();
  await act(async () => { writing.resolve(responseFor(operation)); await pending; });
  expect(result.current.categories).toEqual([first]);
  expect(invalidate).not.toHaveBeenCalled();
});

it('clears a previous collection immediately and keeps the new read loading while obsolete reads and writes finish', async () => {
  const api = gateway();
  const oldRead = deferred<Category[]>();
  const newRead = deferred<Category[]>();
  const mutation = deferred<Category>();
  api.getAll.mockResolvedValueOnce([first]).mockReturnValueOnce(oldRead.promise).mockReturnValueOnce(newRead.promise);
  api.update.mockReturnValue(mutation.promise);
  const { result } = renderHook(() => useCategories(api, vi.fn()));
  await act(async () => { await result.current.loadCategoriesForCollection(1); });
  let old!: Promise<void>;
  let update!: Promise<void>;
  let fresh!: Promise<void>;
  act(() => { old = result.current.loadCategoriesForCollection(1); update = result.current.updateCategory(1, { name: 'Saved' }); });
  act(() => { fresh = result.current.loadCategoriesForCollection(2); });
  expect(result.current.categories).toEqual([]);
  expect(result.current.categoriesLoading).toBe(true);
  await act(async () => { mutation.resolve(saved); await update; oldRead.resolve([first]); await old; });
  expect(result.current.categories).toEqual([]);
  expect(result.current.categoriesLoading).toBe(true);
  await act(async () => { newRead.resolve([other]); await fresh; });
  expect(result.current.categories).toEqual([other]);
});

it('retains a creation that overlaps the first collection read, without duplicating a record already returned by the server', async () => {
  const api = gateway();
  const writing = deferred<Category>();
  const reading = deferred<Category[]>();
  api.create.mockReturnValue(writing.promise);
  api.getAll.mockReturnValue(reading.promise);
  const { result } = renderHook(() => useCategories(api, vi.fn()));
  let create!: Promise<number>;
  let read!: Promise<void>;
  act(() => { create = result.current.addCategory({ collectionId: 1, name: 'Saved' }); read = result.current.loadCategoriesForCollection(1); });
  await act(async () => { reading.resolve([saved, sibling]); await read; });
  await act(async () => { writing.resolve(saved); expect(await create).toBe(1); });
  expect(result.current.categories).toEqual([saved, sibling]);
});

it('accepts an initial scoped creation before any collection is loaded', async () => {
  const api = gateway();
  api.create.mockResolvedValue(saved);
  const { result } = renderHook(() => useCategories(api, vi.fn()));
  await act(async () => { await result.current.addCategory({ collectionId: 1, name: 'Saved' }); });
  expect(result.current.categories).toEqual([saved]);
});

it.each(['create', 'update', 'reorder'] as const)('rejects a %s response belonging to another collection without replacing the active list', async operation => {
  const api = gateway();
  api.getAll.mockResolvedValue([first]);
  api[operation].mockResolvedValue(operation === 'reorder' ? [first, other] : other);
  const { result } = renderHook(() => useCategories(api, vi.fn()));
  await act(async () => { await result.current.loadCategoriesForCollection(1); });
  await act(async () => { await write(result.current, operation); });
  expect(result.current.categories).toEqual([first]);
});

it('leaves successful reads and item caches unchanged after rejected writes', async () => {
  const api = gateway();
  const failure = new Error('Rejected');
  api.getAll.mockResolvedValue([first]);
  for (const operation of operations) api[operation].mockRejectedValue(failure);
  const invalidate = vi.fn();
  const { result } = renderHook(() => useCategories(api, invalidate));
  await act(async () => { await result.current.loadCategoriesForCollection(1); });
  for (const operation of operations) await act(async () => { await expect(write(result.current, operation)).rejects.toBe(failure); });
  expect(result.current.categories).toEqual([first]);
  expect(invalidate).not.toHaveBeenCalled();
});
