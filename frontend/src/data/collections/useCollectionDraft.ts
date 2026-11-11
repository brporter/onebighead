import { useState } from 'react';
import type { Collection } from '../../utils/types';
import type { UpdateCollectionRequest } from '../../api/collections';
import { useAsyncAction } from '../../utils/useAsyncAction';

export type SaveCollection = (id: number, request: UpdateCollectionRequest) => Promise<void>;

/** A single mounted editor owns a stable draft until it saves or is discarded. */
export function useCollectionDraft(collection: Collection, saveCollection: SaveCollection, onSaved: () => void) {
  const [initial] = useState(() => ({ name: collection.name, description: collection.description ?? '', heroImageUrl: collection.heroImageUrl ?? '' }));
  const [draft, setDraft] = useState(initial);
  const action = useAsyncAction();
  const dirty = draft.name !== initial.name || draft.description !== initial.description || draft.heroImageUrl !== initial.heroImageUrl;
  const save = () => action.run(async () => {
    const name = draft.name.trim();
    if (!name) throw new Error('Name is required');
    await saveCollection(collection.collectionId, {
      name, description: draft.description.trim() || undefined, heroImageUrl: draft.heroImageUrl.trim() || undefined,
    });
  }, 'Failed to save collection', onSaved);
  return { draft, setDraft, dirty, save, pending: action.pending, error: action.error };
}
