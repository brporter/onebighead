import { expect, it, vi } from 'vitest';
import { previewPropertyChanges } from '../../src/data/items/previewPropertyChanges';
import { createMockCategory, createMockItem } from '../testUtils/factories';

const old = [{ category: 'Book', name: 'Author', value: 'One' }, { category: 'Book', name: 'Year', value: '2020' }];
const signal = new AbortController().signal;

it('ignores value changes while preserving schema order', async () => {
  const preview = vi.fn().mockResolvedValue({ affectedItemCount: 2 });
  const item = createMockItem({ properties: old.map(property => ({ ...property, value: 'Changed' })) });
  expect(await previewPropertyChanges(old, item, [], { preview }, signal)).toBeNull();
  expect(preview).not.toHaveBeenCalled();
  const reordered = { ...item, properties: [...item.properties].reverse() };
  const result = await previewPropertyChanges(old, reordered, [], { preview }, signal);
  expect(result?.oldProperties).toEqual([{ category: 'Book', name: 'Author' }, { category: 'Book', name: 'Year' }]);
  expect(result?.newProperties).toEqual([...result!.oldProperties].reverse());
  expect(result?.excludeItemId).toBe(item.id);
  expect(result?.scopeOptions).toEqual([{ scope: 'collection', collectionId: 1, label: 'in this collection', count: 2 }]);
});

it('previews category and collection scopes and drops scopes with no affected items', async () => {
  const preview = vi.fn().mockResolvedValueOnce({ affectedItemCount: 2 }).mockResolvedValueOnce({ affectedItemCount: 0 });
  const item = createMockItem({ categoryId: 1, properties: [] });
  const result = await previewPropertyChanges(old, item, [createMockCategory({ name: 'Books' })], { preview }, signal);
  expect(result?.scopeOptions).toEqual([{ scope: 'category', categoryId: 1, label: 'in "Books"', count: 2 }]);
  expect(preview).toHaveBeenCalledWith(expect.objectContaining({ scope: 'category', categoryId: 1, excludeItemId: 1 }), { signal });
  expect(preview).toHaveBeenCalledWith(expect.objectContaining({ scope: 'collection', collectionId: 1, excludeItemId: 1 }), { signal });
});

it('handles removed categories and an empty related-item set', async () => {
  const preview = vi.fn().mockResolvedValue({ affectedItemCount: 1 });
  const item = createMockItem({ categoryId: 4, properties: [{ ...old[0], category: 'Film' }, old[1]] });
  expect((await previewPropertyChanges(old, item, [], { preview }, signal))?.scopeOptions[0].label).toBe('in "this category"');
  preview.mockResolvedValue({ affectedItemCount: 0 });
  expect(await previewPropertyChanges(old, item, [], { preview }, signal)).toBeNull();
});

it('propagates preview failures for a recoverable UI message', async () => {
  const preview = vi.fn().mockRejectedValue(new Error('Offline'));
  await expect(previewPropertyChanges(old, createMockItem(), [], { preview }, signal)).rejects.toThrow('Offline');
});
