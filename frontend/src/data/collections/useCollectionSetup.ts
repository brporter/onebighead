import { useState } from 'react';
import type { Collection, CollectionTheme, SetupCollectionRequest } from '../../utils/types';
import { useAsyncAction } from '../../utils/useAsyncAction';

type SetupCollection = (request: SetupCollectionRequest) => Promise<Collection>;

export function useCollectionSetup(themes: CollectionTheme[], setup: SetupCollection, onCreated: (id: number) => void) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [selectedId, selectTheme] = useState<number | null>(null);
  const general = themes.find(theme => theme.name === 'General');
  const selectedTheme = themes.find(theme => theme.themeId === (selectedId ?? general?.themeId)) ?? null;
  const action = useAsyncAction();
  const dirty = name !== '' || description !== '' || (selectedId !== null && selectedId !== general?.themeId);

  const create = (useDefault: boolean) => action.run(async () => {
    const theme = useDefault ? general : selectedTheme;
    if (!theme) throw new Error(useDefault ? 'Unable to find default theme' : 'Please select a theme');
    const collectionName = useDefault ? name.trim() || 'My Collection' : name.trim();
    if (!collectionName) throw new Error('Name is required');
    return setup({ name: collectionName, description: description.trim(), themeId: theme.themeId });
  }, 'Failed to create collection', collection => onCreated(collection.collectionId));

  return { name, setName, description, setDescription, selectedTheme, selectTheme, dirty, create, pending: action.pending, error: action.error };
}
