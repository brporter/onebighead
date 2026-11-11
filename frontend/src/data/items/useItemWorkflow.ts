import { useEffect, useRef, useState } from 'react';
import type { Category, Item } from '../../utils/types';
import type { bulkUpdatesApi } from '../../api/bulkUpdates';
import type { ItemPropertyChangeOffer } from '../bulkUpdates/types';
import { getErrorMessage } from '../../utils/errorUtils';
import { previewPropertyChanges } from './previewPropertyChanges';

export interface ItemWorkflowPort {
  addItem: (item: Item) => Promise<number>;
  updateItem: (id: number, item: Partial<Item>) => Promise<Item>;
  deleteItem: (id: number) => Promise<void>;
  invalidateItemCache: () => void;
  loadItemsForCategory: (id: number) => Promise<void>;
}

export function useItemWorkflow(item: Item | null, categories: Category[], commands: ItemWorkflowPort,
  previews: Pick<typeof bulkUpdatesApi, 'preview'>, onLeave: (item: Item) => void) {
  const [editing, setEditing] = useState(item?.id === null);
  const [offer, setOffer] = useState<ItemPropertyChangeOffer | null>(null);
  const [previewIssue, setPreviewIssue] = useState<{ message: string; retry: () => void } | null>(null);
  const originalProperties = useRef(item?.properties ?? []);
  const preview = useRef<AbortController | null>(null);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; preview.current?.abort(); };
  }, []);

  async function checkRelatedItems(previous: Item['properties'], updated: Item) {
    preview.current?.abort();
    const controller = new AbortController();
    preview.current = controller;
    setPreviewIssue(null);
    try {
      const result = await previewPropertyChanges(previous, updated, categories, previews, controller.signal);
      if (!controller.signal.aborted) setOffer(result);
    } catch (cause) {
      if (!controller.signal.aborted) setPreviewIssue({
        message: getErrorMessage(cause, 'Unable to check related items'),
        retry: () => { void checkRelatedItems(previous, updated); },
      });
    }
  }

  function beginEdit() {
    if (!item) return;
    preview.current?.abort();
    setOffer(null);
    setPreviewIssue(null);
    originalProperties.current = item.properties.map(property => ({ ...property }));
    setEditing(true);
  }

  function cancelEdit() {
    if (item?.id === null) onLeave(item);
    else setEditing(false);
  }

  async function save(draft: Item) {
    if (!item) throw new Error('The item is no longer available.');
    if (item.id === null) {
      await commands.addItem(draft);
      if (mounted.current) onLeave(draft);
      return;
    }
    const updated = await commands.updateItem(item.id, draft);
    if (!mounted.current) return;
    setEditing(false);
    await checkRelatedItems(originalProperties.current, updated);
  }

  async function remove(id: number) {
    if (!item) throw new Error('The item is no longer available.');
    await commands.deleteItem(id);
    if (mounted.current) onLeave(item);
  }

  function completeBulkUpdate() {
    setOffer(null);
    commands.invalidateItemCache();
    if (item && item.categoryId !== null) void commands.loadItemsForCategory(item.categoryId);
  }

  return { item, editing, beginEdit, cancelEdit, save, remove,
    offer, closeOffer: () => setOffer(null), completeBulkUpdate, previewIssue };
}
