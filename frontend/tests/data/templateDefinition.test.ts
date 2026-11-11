import { act, renderHook, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { createTemplateDraft, newTemplateProperty, sameTemplateDraft, templatePropertyChanges, templateRequest } from '../../src/data/templates/templateDefinition';
import { useTemplateDefinition } from '../../src/data/templates/useTemplateDefinition';
import { createMockItemTemplate } from '../testUtils/factories';
import { deferred } from '../testUtils/deferred';
import type { ItemTemplate } from '../../src/utils/types';

const original = createMockItemTemplate({ properties: [{ category: 'Details', name: 'Author' }, { category: 'Details', name: 'Year' }] });

describe('template draft policy', () => {
  it('copies templates into independent drafts with unique row identities', () => {
    expect(createTemplateDraft(null)).toEqual({ name: '', description: '', properties: [] });
    const draft = createTemplateDraft(original);
    expect(draft.properties.map(property => property.id)).toHaveLength(2);
    expect(new Set(draft.properties.map(property => property.id)).size).toBe(2);
    draft.properties[0].name = 'Changed';
    expect(original.properties[0].name).toBe('Author');
    expect(newTemplateProperty()).toEqual({ id: expect.any(String), name: '', category: '' });
  });

  it('detects ordered schema, name and description edits without treating row IDs as data', () => {
    const draft = createTemplateDraft(original);
    expect(sameTemplateDraft(draft, createTemplateDraft(original))).toBe(true);
    expect(sameTemplateDraft(draft, { ...draft, name: 'New' })).toBe(false);
    expect(sameTemplateDraft(draft, { ...draft, description: 'New' })).toBe(false);
    expect(sameTemplateDraft(draft, { ...draft, properties: [...draft.properties].reverse() })).toBe(false);
    expect(sameTemplateDraft(draft, { ...draft, properties: [] })).toBe(false);
  });

  it('trims requests, rejects incomplete or duplicate fields, and permits empty schemas', () => {
    const draft = { name: ' Books ', description: ' Reading ', properties: [{ id: 'a', category: ' Details ', name: ' Author ' }] };
    expect(templateRequest(draft)).toEqual({ name: 'Books', description: 'Reading', properties: [{ category: 'Details', name: 'Author' }] });
    expect(() => templateRequest({ ...draft, name: ' ' })).toThrow('Name is required');
    expect(() => templateRequest({ ...draft, properties: [{ ...draft.properties[0], category: ' ' }] })).toThrow('All properties');
    expect(() => templateRequest({ ...draft, properties: [{ ...draft.properties[0], name: ' ' }] })).toThrow('All properties');
    expect(() => templateRequest({ ...draft, properties: [...draft.properties, { id: 'b', category: 'Details', name: 'Author' }] })).toThrow('unique');
    expect(templateRequest({ ...draft, properties: [] }).properties).toEqual([]);
  });

  it('tracks renames by stable row identity through reorder, addition and removal', () => {
    const draft = createTemplateDraft(original);
    const unchanged = { ...draft, properties: draft.properties.map(property => ({ ...property, name: ` ${property.name} ` })) };
    expect(templatePropertyChanges(draft, unchanged)).toBeNull();
    const next = { ...draft, properties: [draft.properties[1], { ...draft.properties[0], category: ' Book ', name: ' Writer ' }, { id: 'new', category: ' Details ', name: ' Title ' }] };
    expect(templatePropertyChanges(draft, next)).toEqual({
      oldProperties: original.properties,
      newProperties: [{ category: 'Details', name: 'Year' }, { category: 'Book', name: 'Writer' }, { category: 'Details', name: 'Title' }],
      renameMappings: [{ oldCategory: 'Details', oldName: 'Author', newCategory: 'Book', newName: 'Writer' }],
    });
    expect(templatePropertyChanges(draft, { ...draft, properties: [] })?.renameMappings).toEqual([]);
  });
});

function setup(template: ItemTemplate | null = original) {
  const commands = { createItemTemplate: vi.fn().mockResolvedValue(original), updateItemTemplate: vi.fn().mockResolvedValue(original) };
  const previews = { preview: vi.fn().mockResolvedValue({ affectedItemCount: 0 }) };
  const saved = vi.fn();
  const done = vi.fn();
  const hook = renderHook(() => useTemplateDefinition(template, commands, previews, saved, done));
  const rename = () => act(() => hook.result.current.setDraft(draft => ({ ...draft,
    properties: draft.properties.map((property, i) => i === 0 ? { ...property, name: 'Writer' } : property) })));
  return { ...hook, commands, previews, saved, done, rename };
}

describe('template save workflow', () => {
  it('validates before calling a port and creates once even after repeated submissions', async () => {
    const h = setup(null);
    act(() => h.result.current.retryPreview());
    expect(h.previews.preview).not.toHaveBeenCalled();
    await act(async () => { await h.result.current.save(); });
    expect(h.result.current.error).toBe('Name is required');
    expect(h.commands.createItemTemplate).not.toHaveBeenCalled();
    act(() => h.result.current.setDraft(draft => ({ ...draft, name: ' Book ' })));
    expect(h.result.current.dirty).toBe(true);
    const pending = deferred<ItemTemplate>();
    h.commands.createItemTemplate.mockReturnValue(pending.promise);
    let saving: Promise<void> | undefined;
    act(() => { saving = h.result.current.save(); void h.result.current.save(); });
    expect(h.result.current.saving).toBe(true);
    expect(h.commands.createItemTemplate).toHaveBeenCalledTimes(1);
    expect(h.commands.createItemTemplate).toHaveBeenCalledWith({ name: 'Book', description: '', properties: [] });
    await act(async () => { pending.resolve(original); await saving; });
    expect(h.result.current.dirty).toBe(false);
    expect(h.result.current.saving).toBe(false);
    expect(h.saved).toHaveBeenCalledTimes(1);
    expect(h.done).toHaveBeenCalledTimes(1);
    await act(async () => { await h.result.current.save(); });
    expect(h.commands.createItemTemplate).toHaveBeenCalledTimes(1);
    expect(h.previews.preview).not.toHaveBeenCalled();
  });

  it('retains a failed draft, allows retry, and skips previews for metadata-only changes', async () => {
    const h = setup();
    h.commands.updateItemTemplate.mockRejectedValueOnce(new Error('Save failed'));
    act(() => h.result.current.setDraft(draft => ({ ...draft, description: 'Updated' })));
    await act(async () => { await h.result.current.save(); });
    expect(h.result.current.error).toBe('Save failed');
    expect(h.result.current.draft.description).toBe('Updated');
    expect(h.result.current.dirty).toBe(true);
    expect(h.saved).not.toHaveBeenCalled();
    await act(async () => { await h.result.current.save(); });
    expect(h.commands.updateItemTemplate).toHaveBeenLastCalledWith(original.itemTemplateId, { name: original.name, description: 'Updated', properties: original.properties });
    expect(h.result.current.error).toBeNull();
    expect(h.previews.preview).not.toHaveBeenCalled();
    expect(h.done).toHaveBeenCalledTimes(1);
  });

  it('uses the saved template key for a copy and supplies rename mappings for related items', async () => {
    const h = setup({ ...original, isSystem: true });
    h.commands.updateItemTemplate.mockResolvedValue({ ...original, templateKey: 'saved-key', isSystem: false });
    h.previews.preview.mockResolvedValue({ affectedItemCount: 7 });
    h.rename();
    await act(async () => { await h.result.current.save(); });
    expect(h.previews.preview).toHaveBeenCalledWith({ scope: 'template', templateKey: 'saved-key' }, { signal: expect.any(AbortSignal) });
    expect(h.result.current.scopeOptions).toEqual([{ scope: 'template', templateKey: 'saved-key', label: 'created from this template', count: 7 }]);
    expect(h.result.current.saved?.changes.renameMappings).toEqual([{ oldCategory: 'Details', oldName: 'Author', newCategory: 'Details', newName: 'Writer' }]);
    expect(h.result.current.dirty).toBe(false);
    expect(h.done).not.toHaveBeenCalled();
  });

  it('reports preview failure and retries only the check after a successful save', async () => {
    const h = setup();
    h.previews.preview.mockRejectedValueOnce('Offline');
    h.rename();
    await act(async () => { await h.result.current.save(); });
    expect(h.result.current.previewError).toBe('Unable to check related items');
    expect(h.result.current.error).toBeNull();
    expect(h.saved).toHaveBeenCalledTimes(1);
    expect(h.done).not.toHaveBeenCalled();
    act(() => h.result.current.retryPreview());
    await waitFor(() => expect(h.done).toHaveBeenCalledTimes(1));
    expect(h.result.current.previewError).toBeNull();
    expect(h.commands.updateItemTemplate).toHaveBeenCalledTimes(1);
    expect(h.previews.preview).toHaveBeenCalledTimes(2);
  });

  it('ignores a save that finishes after unmount', async () => {
    const h = setup();
    const pending = deferred<ItemTemplate>();
    h.commands.updateItemTemplate.mockReturnValue(pending.promise);
    h.rename();
    act(() => { void h.result.current.save(); });
    h.unmount();
    await act(async () => pending.resolve(original));
    expect(h.saved).not.toHaveBeenCalled();
    expect(h.previews.preview).not.toHaveBeenCalled();
    expect(h.done).not.toHaveBeenCalled();
  });

  it.each(['resolve', 'reject'] as const)('aborts obsolete previews and ignores late %s after unmount', async outcome => {
    const h = setup();
    h.previews.preview.mockRejectedValueOnce(new Error('Disconnected'));
    h.rename();
    await act(async () => { await h.result.current.save(); });
    expect(h.result.current.previewError).toBe('Disconnected');
    const pending = deferred<{ affectedItemCount: number }>();
    h.previews.preview.mockReturnValueOnce(pending.promise);
    act(() => h.result.current.retryPreview());
    expect(h.result.current.previewLoading).toBe(true);
    const signal = h.previews.preview.mock.calls.slice(-1)[0][1].signal;
    h.unmount();
    expect(signal.aborted).toBe(true);
    await act(async () => {
      if (outcome === 'resolve') pending.resolve({ affectedItemCount: 4 });
      else pending.reject(new Error('Too late'));
    });
    expect(h.done).not.toHaveBeenCalled();
  });
});
