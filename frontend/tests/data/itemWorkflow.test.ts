import { act, renderHook, waitFor } from '@testing-library/react';
import { useState } from 'react';
import { expect, it, vi } from 'vitest';
import { useItemWorkflow, type ItemWorkflowPort } from '../../src/data/items/useItemWorkflow';
import type { BulkUpdatePreviewResponse } from '../../src/api/bulkUpdates';
import { createMockItem, createMockCategory } from '../testUtils/factories';
import { deferred } from '../testUtils/deferred';
import type { Item } from '../../src/utils/types';

const original = createMockItem({ categoryId: 1, properties: [{ category: 'Book', name: 'Author', value: 'One' }] });
const edited = { ...original, name: 'Updated', properties: [{ category: 'Book', name: 'Writer', value: 'One' }] };
function setup(item: Item | null = original) {
  const commands = { addItem: vi.fn().mockResolvedValue(2), updateItem: vi.fn().mockResolvedValue(edited),
    deleteItem: vi.fn().mockResolvedValue(undefined), invalidateItemCache: vi.fn(),
    loadItemsForCategory: vi.fn().mockResolvedValue(undefined) } satisfies ItemWorkflowPort;
  const previews = { preview: vi.fn().mockResolvedValue({ affectedItemCount: 2 }) };
  const leave = vi.fn();
  return { commands, previews, leave, ...renderHook(() => {
    const [source, setSource] = useState(item);
    const workflow = useItemWorkflow(source, [createMockCategory()], {
      ...commands,
      updateItem: async (id, draft) => {
        const saved = await commands.updateItem(id, draft);
        setSource(saved);
        return saved;
      },
    }, previews, leave);
    return { ...workflow, setSource };
  }) };
}

it('keeps an unavailable item read-only and rejects stale editor actions', async () => {
  const { result, commands, leave } = setup(null);
  expect(result.current.editing).toBe(false);
  act(() => result.current.beginEdit());
  expect(result.current.editing).toBe(false);
  act(() => result.current.cancelEdit());
  await expect(result.current.save(edited)).rejects.toThrow('no longer available');
  await expect(result.current.remove(1)).rejects.toThrow('no longer available');
  act(() => result.current.completeBulkUpdate());
  expect(commands.updateItem).not.toHaveBeenCalled();
  expect(commands.deleteItem).not.toHaveBeenCalled();
  expect(commands.loadItemsForCategory).not.toHaveBeenCalled();
  expect(leave).not.toHaveBeenCalled();
});

it('uses refreshed source data after saving, including the next edit and return destination', async () => {
  const { result, leave, previews } = setup();
  act(() => result.current.beginEdit());
  await act(async () => result.current.save(edited));
  const published = { ...edited, name: 'Fresh from the server', categoryId: 2, effectiveIsPublic: true,
    properties: [{ category: 'Book', name: 'Creator', value: 'Two' }] };
  act(() => result.current.setSource(published));
  expect(result.current.item).toBe(published);
  previews.preview.mockClear();
  act(() => result.current.beginEdit());
  await act(async () => result.current.save(edited));
  expect(result.current.offer?.oldProperties).toEqual([{ category: 'Book', name: 'Creator' }]);
  act(() => result.current.setSource(published));
  await act(async () => result.current.remove(1));
  expect(leave).toHaveBeenLastCalledWith(published);
});

it('keeps editing separate from saved details and offers related-item updates after save', async () => {
  const { result, commands, leave } = setup();
  act(() => result.current.beginEdit());
  expect(result.current.editing).toBe(true);
  act(() => result.current.cancelEdit());
  expect(result.current.editing).toBe(false);
  expect(leave).not.toHaveBeenCalled();
  act(() => result.current.beginEdit());
  await act(async () => result.current.save(edited));
  expect(commands.updateItem).toHaveBeenCalledWith(1, edited);
  expect(result.current.item).toEqual(edited);
  expect(result.current.editing).toBe(false);
  expect(result.current.offer?.scopeOptions).toHaveLength(2);
  act(() => result.current.closeOffer());
  expect(result.current.offer).toBeNull();
  act(() => result.current.completeBulkUpdate());
  expect(commands.invalidateItemCache).toHaveBeenCalledOnce();
  expect(commands.loadItemsForCategory).toHaveBeenCalledWith(1);
  act(() => result.current.beginEdit());
  await act(async () => result.current.save(edited));
  expect(result.current.offer).toBeNull(); // A second value-only save has no schema changes.
});

it('refreshes uncategorized items without requesting a nonexistent category', () => {
  const { result, commands } = setup({ ...original, categoryId: null });
  act(() => result.current.completeBulkUpdate());
  expect(commands.invalidateItemCache).toHaveBeenCalledOnce();
  expect(commands.loadItemsForCategory).not.toHaveBeenCalled();
});

it('keeps the successful save visible if the preview fails and retries the preview alone', async () => {
  const { result, previews, commands } = setup();
  previews.preview.mockRejectedValueOnce(new Error('Preview offline'));
  act(() => result.current.beginEdit());
  await act(async () => result.current.save(edited));
  expect(result.current.item).toEqual(edited);
  expect(result.current.editing).toBe(false);
  expect(result.current.previewIssue?.message).toBe('Preview offline');
  act(() => result.current.previewIssue!.retry());
  await waitFor(() => expect(result.current.offer).not.toBeNull());
  expect(result.current.previewIssue).toBeNull();
  expect(commands.updateItem).toHaveBeenCalledOnce();
});

it.each(['success', 'failure'])('ignores a preview %s after editing restarts', async outcome => {
  const { result, previews } = setup();
  const pending = deferred<BulkUpdatePreviewResponse>();
  previews.preview.mockReturnValue(pending.promise);
  let save!: Promise<void>;
  await act(async () => { save = result.current.save(edited); });
  const signal = previews.preview.mock.calls[0][1].signal as AbortSignal;
  act(() => result.current.beginEdit());
  expect(signal.aborted).toBe(true);
  await act(async () => {
    if (outcome === 'success') pending.resolve({ affectedItemCount: 2 }); else pending.reject(new Error('Late error'));
    await save;
  });
  expect(result.current.offer).toBeNull();
  expect(result.current.previewIssue).toBeNull();
  expect(result.current.editing).toBe(true);
});

it('passes mutation errors to the editor while keeping the original details', async () => {
  const { result, commands, previews, leave } = setup();
  commands.updateItem.mockRejectedValue(new Error('Save failed'));
  act(() => result.current.beginEdit());
  await act(async () => { await expect(result.current.save(edited)).rejects.toThrow('Save failed'); });
  expect(result.current.item).toEqual(original);
  expect(result.current.editing).toBe(true);
  expect(previews.preview).not.toHaveBeenCalled();
  commands.deleteItem.mockRejectedValue(new Error('Delete failed'));
  await act(async () => { await expect(result.current.remove(1)).rejects.toThrow('Delete failed'); });
  expect(leave).not.toHaveBeenCalled();
});

it('creates new items and navigates using the saved category', async () => {
  const item = { ...original, id: null };
  const { result, commands, previews, leave } = setup(item);
  expect(result.current.editing).toBe(true);
  act(() => result.current.cancelEdit());
  expect(leave).toHaveBeenLastCalledWith(item);
  const draft = { ...item, categoryId: 2 };
  await act(async () => result.current.save(draft));
  expect(commands.addItem).toHaveBeenCalledWith(draft);
  expect(leave).toHaveBeenLastCalledWith(draft);
  expect(previews.preview).not.toHaveBeenCalled();
});

it('navigates after deleting an existing item', async () => {
  const { result, commands, leave } = setup();
  await act(async () => result.current.remove(1));
  expect(commands.deleteItem).toHaveBeenCalledWith(1);
  expect(leave).toHaveBeenCalledWith(original);
});

it.each(['create', 'update', 'delete'] as const)('does not navigate or preview after a %s completes on an abandoned page', async operation => {
  const { result, commands, previews, leave, unmount } = setup({ ...original, id: operation === 'create' ? null : 1 });
  const pending = deferred<typeof edited>();
  commands.addItem.mockImplementation(async () => { await pending.promise; return 2; });
  commands.updateItem.mockReturnValue(pending.promise);
  commands.deleteItem.mockImplementation(async () => { await pending.promise; });
  let request!: Promise<void>;
  act(() => { request = operation === 'delete' ? result.current.remove(1) : result.current.save(edited); });
  unmount();
  await act(async () => { pending.resolve(edited); await request; });
  expect(leave).not.toHaveBeenCalled();
  expect(previews.preview).not.toHaveBeenCalled();
});

it('aborts preview work on unmount', async () => {
  const { result, previews, unmount } = setup();
  const pending = deferred<BulkUpdatePreviewResponse>();
  previews.preview.mockReturnValue(pending.promise);
  let request!: Promise<void>;
  await act(async () => { request = result.current.save(edited); });
  const signal = previews.preview.mock.calls[0][1].signal as AbortSignal;
  unmount();
  expect(signal.aborted).toBe(true);
  await act(async () => { pending.resolve({ affectedItemCount: 2 }); await request; });
  expect(result.current.offer).toBeNull();
});
