import { act, renderHook } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { useCollections } from '../../src/data/collections/useCollections';
import { createMockCollection } from '../testUtils/factories';
import { deferred } from '../testUtils/deferred';
import type { CollectionGateway } from '../../src/data/contracts';
import type { Collection } from '../../src/utils/types';

function gateway() {
  return { getAll: vi.fn(), create: vi.fn(), setup: vi.fn(), update: vi.fn(), delete: vi.fn() } satisfies CollectionGateway;
}

describe('collections module', () => {
  it('deduplicates concurrent loads and permits retries after a failed load', async () => {
    const api = gateway();
    const response = deferred<Collection[]>();
    api.getAll.mockReturnValueOnce(response.promise).mockResolvedValueOnce([createMockCollection()]);
    const { result } = renderHook(() => useCollections(api));
    let first!: Promise<void>;
    act(() => {
      first = result.current.loadCollections();
      expect(result.current.loadCollections()).toBe(first);
    });
    expect(api.getAll).toHaveBeenCalledTimes(1);
    await act(async () => { response.reject(new Error('Offline')); await first; });
    expect(result.current.collectionsError).toBe('Offline');
    await act(async () => { await result.current.loadCollections(); });
    expect(result.current.collections).toHaveLength(1);
    expect(result.current.collectionsError).toBeNull();
  });

  it('creates ordinary and themed collections', async () => {
    const api = gateway();
    const ordinary = createMockCollection({ collectionId: 1 });
    const themed = createMockCollection({ collectionId: 2 });
    api.create.mockResolvedValue(ordinary);
    api.setup.mockResolvedValue(themed);
    const { result } = renderHook(() => useCollections(api));
    await act(async () => { expect(await result.current.addCollection('Books', 'Shelf', '/hero')).toBe(ordinary); });
    expect(api.create).toHaveBeenCalledWith({ name: 'Books', description: 'Shelf', heroImageUrl: '/hero' });
    const request = { name: 'Records', themeId: 1 };
    await act(async () => { expect(await result.current.setupCollection(request)).toBe(themed); });
    expect(api.setup).toHaveBeenCalledWith(request);
    expect(result.current.collections).toEqual([ordinary, themed]);
  });

  it('updates and clears the selected collection only when its identity matches', async () => {
    const api = gateway();
    const first = createMockCollection({ collectionId: 1 });
    const second = createMockCollection({ collectionId: 2 });
    const updated = { ...first, name: 'Updated' };
    api.getAll.mockResolvedValue([first, second]);
    api.update.mockResolvedValue(updated);
    const { result } = renderHook(() => useCollections(api));
    await act(async () => { await result.current.loadCollections(); await result.current.updateCollection(1, { name: updated.name }); });
    expect(result.current.currentCollection).toBeNull();
    act(() => result.current.setCurrentCollection(second));
    await act(async () => { await result.current.updateCollection(1, { name: updated.name }); });
    expect(result.current.currentCollection).toBe(second);
    act(() => result.current.setCurrentCollection(first));
    await act(async () => { await result.current.updateCollection(1, { name: updated.name }); });
    expect(result.current.currentCollection).toBe(updated);
    expect(result.current.collections).toEqual([updated, second]);
    await act(async () => { await result.current.deleteCollection(2); });
    expect(result.current.currentCollection).toBe(updated);
    await act(async () => { await result.current.deleteCollection(1); });
    expect(result.current.currentCollection).toBeNull();
    await act(async () => { await result.current.deleteCollection(99); });
    expect(result.current.collections).toEqual([]);
  });

  it('does not change selection when an update completes after navigation', async () => {
    const api = gateway();
    const response = deferred<Collection>();
    api.update.mockReturnValue(response.promise);
    const { result } = renderHook(() => useCollections(api));
    act(() => result.current.setCurrentCollection(createMockCollection({ collectionId: 1 })));
    let request!: Promise<void>;
    act(() => { request = result.current.updateCollection(1, { name: 'Updated' }); });
    const next = createMockCollection({ collectionId: 2 });
    act(() => result.current.setCurrentCollection(next));
    await act(async () => { response.resolve(createMockCollection()); await request; });
    expect(result.current.currentCollection).toBe(next);
  });
});

it('requires a new post-write read, refreshes selection, and ignores older results', async () => {
  const api = gateway();
  const old = deferred<Collection[]>();
  const selected = createMockCollection();
  const fresh = { ...selected, effectiveIsPublic: true, name: 'Fresh' };
  api.getAll.mockReturnValueOnce(old.promise).mockResolvedValueOnce([fresh]).mockResolvedValueOnce([]);
  const { result } = renderHook(() => useCollections(api));
  act(() => result.current.setCurrentCollection(selected));
  let oldRequest!: Promise<void>;
  act(() => { oldRequest = result.current.loadCollections(); });
  const options = { signal: new AbortController().signal, throwOnError: true };
  await act(async () => { await result.current.loadCollections(options); });
  expect(api.getAll).toHaveBeenLastCalledWith(options);
  expect(result.current.currentCollection).toBe(fresh);
  await act(async () => { old.resolve([selected]); await oldRequest; });
  expect(result.current.currentCollection).toBe(fresh);
  expect(result.current.collections).toEqual([fresh]);
  await act(async () => { await result.current.loadCollections(options); });
  expect(result.current.currentCollection).toBeNull();
  api.getAll.mockRejectedValue(new Error('Offline'));
  await act(async () => { await expect(result.current.loadCollections(options)).rejects.toThrow('Offline'); });
});

it.each(['create', 'setup', 'update', 'delete'] as const)('preserves a confirmed %s when an older full-list read arrives', async operation => {
  const api = gateway();
  const old = deferred<Collection[]>();
  const original = createMockCollection({ collectionId: 1, name: 'Original' });
  const saved = { ...original, name: 'Saved' };
  const unrelated = createMockCollection({ collectionId: 2, name: 'Unrelated' });
  api.getAll.mockReturnValue(old.promise);
  api.create.mockResolvedValue(saved);
  api.setup.mockResolvedValue(saved);
  api.update.mockResolvedValue(saved);
  const { result } = renderHook(() => useCollections(api));
  act(() => result.current.setCurrentCollection(original));
  let read!: Promise<void>;
  act(() => { read = result.current.loadCollections(); });
  await act(async () => {
    if (operation === 'create') await result.current.addCollection('Saved');
    else if (operation === 'setup') await result.current.setupCollection({ name: 'Saved', themeId: 1 });
    else if (operation === 'update') await result.current.updateCollection(1, { name: 'Saved' });
    else await result.current.deleteCollection(1);
  });
  expect(result.current.collections).toEqual(operation === 'delete' ? [] : [saved]);
  await act(async () => { old.resolve([original, unrelated]); await read; });
  expect(result.current.collections).toEqual(operation === 'delete' ? [unrelated] : [saved, unrelated]);
  expect(result.current.currentCollection).toEqual(operation === 'delete' ? null : saved);
  expect(result.current.collectionsLoading).toBe(false);
});

it('adds a confirmed creation to an older list that does not yet include it, while retaining the server’s other collections', async () => {
  const api = gateway();
  const response = deferred<Collection[]>();
  const saved = createMockCollection({ collectionId: 3 });
  const unrelated = createMockCollection({ collectionId: 1 });
  api.getAll.mockReturnValue(response.promise);
  api.create.mockResolvedValue(saved);
  const { result } = renderHook(() => useCollections(api));
  let read!: Promise<void>;
  act(() => { read = result.current.loadCollections(); });
  await act(async () => { await result.current.addCollection('Saved'); });
  await act(async () => { response.resolve([unrelated]); await read; });
  expect(result.current.collections).toEqual([unrelated, saved]);
});

it.each(['create', 'setup'] as const)('does not duplicate a %s already observed by a list read before its response arrives', async operation => {
  const api = gateway();
  const response = deferred<Collection>();
  const saved = createMockCollection();
  api.create.mockReturnValue(response.promise);
  api.setup.mockReturnValue(response.promise);
  api.getAll.mockResolvedValue([saved]);
  const { result } = renderHook(() => useCollections(api));
  let write!: Promise<Collection>;
  act(() => { write = operation === 'create' ? result.current.addCollection('Saved') : result.current.setupCollection({ name: 'Saved', themeId: 1 }); });
  await act(async () => { await result.current.loadCollections(); });
  await act(async () => { response.resolve(saved); await write; });
  expect(result.current.collections).toEqual([saved]);
});

it('does not let a failed mutation replace or invalidate a valid list read', async () => {
  const api = gateway();
  const response = deferred<Collection[]>();
  const original = createMockCollection();
  api.getAll.mockReturnValue(response.promise);
  api.update.mockRejectedValue(new Error('Update rejected'));
  const { result } = renderHook(() => useCollections(api));
  let read!: Promise<void>;
  act(() => { read = result.current.loadCollections(); });
  await act(async () => { await expect(result.current.updateCollection(1, { name: 'Unsaved' })).rejects.toThrow('Update rejected'); });
  await act(async () => { response.resolve([original]); await read; });
  expect(result.current.collections).toEqual([original]);
  expect(result.current.collectionsError).toBeNull();
});

it('deduplicates against the latest forced refresh and does not let an obsolete completion retire it', async () => {
  const api = gateway();
  const first = deferred<Collection[]>();
  const second = deferred<Collection[]>();
  api.getAll.mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise).mockResolvedValueOnce([]);
  const { result } = renderHook(() => useCollections(api));
  let old!: Promise<void>;
  let current!: Promise<void>;
  act(() => {
    old = result.current.loadCollections();
    current = result.current.loadCollections({});
    expect(result.current.loadCollections()).toBe(current);
  });
  await act(async () => { first.resolve([]); await old; });
  act(() => { expect(result.current.loadCollections()).toBe(current); });
  expect(api.getAll).toHaveBeenCalledTimes(2);
  await act(async () => { second.resolve([]); await current; });
  await act(async () => { await result.current.loadCollections(); });
  expect(api.getAll).toHaveBeenCalledTimes(3);
});

it.each(['create', 'setup', 'update', 'delete'] as const)('ignores a late %s after the workspace data provider unmounts', async operation => {
  const api = gateway();
  const response = deferred<Collection>();
  const saved = createMockCollection();
  api.create.mockReturnValue(response.promise);
  api.setup.mockReturnValue(response.promise);
  api.update.mockReturnValue(response.promise);
  api.delete.mockReturnValue(response.promise);
  const { result, unmount } = renderHook(() => useCollections(api));
  act(() => result.current.setCurrentCollection(saved));
  let write!: Promise<unknown>;
  act(() => {
    if (operation === 'create') write = result.current.addCollection('Saved');
    else if (operation === 'setup') write = result.current.setupCollection({ name: 'Saved', themeId: 1 });
    else if (operation === 'update') write = result.current.updateCollection(1, { name: 'Saved' });
    else write = result.current.deleteCollection(1);
  });
  unmount();
  await act(async () => { response.resolve(saved); await write; });
  expect(result.current.collections).toEqual([]);
  expect(result.current.currentCollection).toBe(saved);
});
