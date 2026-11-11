import { act, renderHook } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { useCategories } from '../../src/data/categories/useCategories';
import { useTemplates } from '../../src/data/templates/useTemplates';
import { useThemes } from '../../src/data/themes/useThemes';
import { createMockCategory, createMockItemTemplate, createMockCollectionTheme } from '../testUtils/factories';
import type { CategoryGateway, TemplateGateway } from '../../src/data/contracts';

describe('categories module', () => {
  it('loads and maintains categories through creation, editing, reordering and deletion', async () => {
    const first = createMockCategory();
    const second = createMockCategory({ categoryId: 2 });
    const updated = { ...second, name: 'Updated' };
    const api = { getAll: vi.fn().mockResolvedValue([first]), create: vi.fn().mockResolvedValue(second),
      update: vi.fn().mockResolvedValue(updated), delete: vi.fn(), reorder: vi.fn().mockResolvedValue([updated, first]),
      getTemplates: vi.fn().mockResolvedValue([3]) } satisfies CategoryGateway;
    const invalidate = vi.fn();
    const { result } = renderHook(() => useCategories(api, invalidate));
    await act(async () => { await result.current.loadCategoriesForCollection(1); });
    expect(api.getAll).toHaveBeenCalledWith(1, undefined);
    expect(result.current.categories).toEqual([first]);
    const options = { signal: new AbortController().signal, throwOnError: true };
    await act(async () => { await result.current.loadCategoriesForCollection(1, options); });
    expect(api.getAll).toHaveBeenLastCalledWith(1, options);
    await act(async () => { expect(await result.current.addCategory(second)).toBe(2); });
    await act(async () => { await result.current.updateCategory(2, updated); });
    expect(result.current.categories).toEqual([first, updated]);
    expect(invalidate).toHaveBeenCalledTimes(1);
    await act(async () => { await result.current.reorderCategories([{ categoryId: 2, sortOrder: 0 }]); });
    expect(api.reorder).toHaveBeenCalledWith({ categories: [{ categoryId: 2, sortOrder: 0 }] });
    expect(result.current.categories).toEqual([updated, first]);
    expect(await result.current.getCategoryTemplates(2)).toEqual([3]);
    expect(api.getTemplates).toHaveBeenCalledWith(2, undefined);
    await act(async () => { await result.current.deleteCategory(2); });
    expect(result.current.categories).toEqual([first]);
    expect(invalidate).toHaveBeenCalledTimes(2);
  });
});

describe('templates module', () => {
  it('delegates template reads and writes without a second catalog cache', async () => {
    const first = createMockItemTemplate({ itemTemplateId: 1, name: 'Zulu' });
    const second = createMockItemTemplate({ itemTemplateId: 2, name: 'Alpha' });
    const updated = { ...first, name: 'Aardvark' };
    const api = { getAll: vi.fn().mockResolvedValue([first]), getForCollection: vi.fn().mockResolvedValue([second]),
      create: vi.fn().mockResolvedValue(second), update: vi.fn().mockResolvedValue(updated), delete: vi.fn(),
      associateWithCollection: vi.fn(), disassociateFromCollection: vi.fn() } satisfies TemplateGateway;
    const { result, rerender } = renderHook(({ gateway }) => useTemplates(gateway), { initialProps: { gateway: api } });
    const operations = result.current;
    rerender({ gateway: api });
    expect(result.current).toBe(operations);
    await act(async () => { expect(await result.current.createItemTemplate(second)).toBe(second); });
    await act(async () => { expect(await result.current.updateItemTemplate(1, updated)).toBe(updated); });
    await act(async () => { await result.current.deleteItemTemplate(1); });
    expect(await result.current.loadCollectionTemplates(9)).toEqual([second]);
    expect(api.getForCollection).toHaveBeenCalledWith(9, undefined);
    const options = { signal: new AbortController().signal };
    expect(await result.current.fetchItemTemplates(options)).toEqual([first]);
    expect(api.getAll).toHaveBeenLastCalledWith(undefined, options);
    await result.current.associateTemplateWithCollection(9, 2);
    expect(api.associateWithCollection).toHaveBeenCalledWith(9, 2);
    await result.current.disassociateTemplateFromCollection(9, 2);
    expect(api.disassociateFromCollection).toHaveBeenCalledWith(9, 2);
    expect(api.getAll).toHaveBeenCalledTimes(1);
    const replacement = { ...api, getAll: vi.fn().mockResolvedValue([second]) };
    rerender({ gateway: replacement });
    expect(await result.current.fetchItemTemplates(options)).toEqual([second]);
    expect(replacement.getAll).toHaveBeenCalledWith(undefined, options);
  });
});

describe('themes module', () => {
  it('loads themes through the supplied gateway', async () => {
    const theme = createMockCollectionTheme();
    const api = { getAll: vi.fn().mockResolvedValue([theme]) };
    const { result } = renderHook(() => useThemes(api));
    await act(async () => { await result.current.loadThemes(); });
    expect(result.current.themes).toEqual([theme]);
    expect(result.current.themesLoading).toBe(false);
    expect(result.current.themesError).toBeNull();
  });
});
