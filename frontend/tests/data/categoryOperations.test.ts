import { expect, it, vi } from 'vitest';
import { categoryOperation, type CategoryManagerPort } from '../../src/data/categories/categoryOperations';
import { availableCategoryParents, validateCategoryName } from '../../src/data/categories/categoryDraft';
import { createMockCategory as category } from '../testUtils';

const categories = [category({ categoryId: 1, collectionId: 1, name: 'Books', sortOrder: 2 }),
  category({ categoryId: 2, collectionId: 1, name: 'Cameras', sortOrder: 1 }),
  category({ categoryId: 3, collectionId: 1, parentCategoryId: 1 }),
  category({ categoryId: 4, collectionId: 1, parentCategoryId: 3 }),
  category({ categoryId: 99, collectionId: 1, isSystem: true }), category({ categoryId: 100, collectionId: 2 })];
const draft = { name: 'Books', description: '', parentCategoryId: null, itemTemplateIds: [] };
function port() {
  return { categories, addCategory: vi.fn().mockResolvedValue(5), updateCategory: vi.fn().mockResolvedValue(undefined),
    deleteCategory: vi.fn().mockResolvedValue(undefined), reorderCategories: vi.fn().mockResolvedValue(undefined),
    loadCategoriesForCollection: vi.fn().mockResolvedValue(undefined) } satisfies CategoryManagerPort;
}

it('shares validation and filters unavailable parents, including descendants and other collections', () => {
  expect(validateCategoryName(' ')).toBe('Name is required');
  expect(validateCategoryName(' Unassigned ITEMS ')).toContain('reserved');
  expect(validateCategoryName('Books')).toBeNull();
  expect(availableCategoryParents(categories, 1, categories[0]).map(c => c.categoryId)).toEqual([2]);
  expect(availableCategoryParents(categories, 1, null).map(c => c.categoryId)).toEqual([1, 2, 3, 4]);
});

it('creates once and resumes ordering and required refresh without repeating confirmed steps', async () => {
  const api = port();
  api.reorderCategories.mockRejectedValueOnce(new Error('Order unavailable'));
  api.loadCategoriesForCollection.mockRejectedValueOnce(new Error('Read unavailable'));
  const operation = categoryOperation(api, 1, categories, { type: 'quick-create', name: 'New' });
  expect(operation.hasSaved).toBe(false);
  await expect(operation.run()).rejects.toThrow('Order unavailable');
  expect(operation.hasSaved).toBe(true);
  expect(api.addCategory).toHaveBeenCalledExactlyOnceWith({ collectionId: 1, name: 'New', description: '', parentCategoryId: null, itemTemplateIds: [] });
  expect(api.reorderCategories).toHaveBeenCalledWith([{ categoryId: 5, sortOrder: 0 }, { categoryId: 2, sortOrder: 1 }, { categoryId: 1, sortOrder: 2 }]);
  await expect(operation.run()).rejects.toThrow('Read unavailable');
  await operation.run();
  await operation.run();
  expect(api.addCategory).toHaveBeenCalledTimes(1);
  expect(api.reorderCategories).toHaveBeenCalledTimes(2);
  expect(api.loadCategoriesForCollection).toHaveBeenCalledTimes(2);
  expect(api.loadCategoriesForCollection).toHaveBeenLastCalledWith(1, { throwOnError: true });
});

it.each([null, 1])('saves category %s and only reloads when the write has succeeded', async categoryId => {
  const api = port();
  const operation = categoryOperation(api, 1, categories, { type: 'save', categoryId, draft });
  const write = categoryId === null ? api.addCategory : api.updateCategory;
  write.mockRejectedValueOnce(new Error('Offline'));
  await expect(operation.run()).rejects.toThrow('Offline');
  expect(operation.hasSaved).toBe(false);
  expect(api.loadCategoriesForCollection).not.toHaveBeenCalled();
  await operation.run();
  if (categoryId === null) expect(write).toHaveBeenLastCalledWith({ collectionId: 1, ...draft });
  else expect(write).toHaveBeenLastCalledWith(1, draft);
});

it('delegates deletion and sibling reorder, then refreshes inherited category state', async () => {
  const api = port();
  await categoryOperation(api, 1, categories, { type: 'delete', categoryId: 3 }).run();
  expect(api.deleteCategory).toHaveBeenCalledWith(3);
  const updates = [{ categoryId: 1, sortOrder: 0 }, { categoryId: 2, sortOrder: 1 }];
  await categoryOperation(api, 1, categories, { type: 'reorder', updates }).run();
  expect(api.reorderCategories).toHaveBeenCalledWith(updates);
  expect(api.loadCategoriesForCollection).toHaveBeenCalledTimes(2);
});

it.each([[2, false, [3, 2, 1]], [2, true, [2, 3, 1]], [undefined, undefined, [2, 1, 3]], [100, false, [2, 1, 3]]] as const)(
  'moves once and inserts relative to %s (%s)', async (insertAtCategoryId, insertAfter, orderedIds) => {
    const api = port();
    api.reorderCategories.mockRejectedValueOnce(new Error('Order failed'));
    const operation = categoryOperation(api, 1, categories, { type: 'reparent', categoryId: 3, parentId: null, insertAtCategoryId, insertAfter });
    await expect(operation.run()).rejects.toThrow('Order failed');
    await operation.run();
    expect(api.updateCategory).toHaveBeenCalledExactlyOnceWith(3, { name: categories[2].name, description: categories[2].description, parentCategoryId: null, itemTemplateIds: [] });
    expect(api.reorderCategories).toHaveBeenLastCalledWith(orderedIds.map((categoryId, sortOrder) => ({ categoryId, sortOrder })));
  });

it.each([99, 100, 500])('rejects a missing or unavailable category %s before mutating', async categoryId => {
  const api = port();
  await expect(categoryOperation(api, 1, categories, { type: 'reparent', categoryId, parentId: null }).run()).rejects.toThrow('no longer available');
  expect(api.updateCategory).not.toHaveBeenCalled();
});

it('does not offer missing, cyclic, or system ancestry as a category parent', () => {
  const source = [category({ categoryId: 1 }), category({ categoryId: 2, parentCategoryId: 3 }),
    category({ categoryId: 3, parentCategoryId: 2 }), category({ categoryId: 4, parentCategoryId: 99 }),
    category({ categoryId: 5, parentCategoryId: 4 }), category({ categoryId: 6, isSystem: true }),
    category({ categoryId: 7, parentCategoryId: 6 })];
  expect(availableCategoryParents(source, 1, null).map(value => value.categoryId)).toEqual([1]);
  expect(availableCategoryParents(source, 1, source[1]).map(value => value.categoryId)).toEqual([1]);
});
