import { useCallback, useState } from 'react';
import type { Category } from '../../utils/types';
import { useAsyncData } from '../../utils/useAsyncData';
import { useAsyncAction } from '../../utils/useAsyncAction';
import { categoryOperation, type CategoryCommand, type CategoryManagerPort } from './categoryOperations';

type Editor = { type: 'tree' } | { type: 'quick' } | { type: 'form'; category: Category | null; initialName: string };
type Destination = 'tree' | 'close';

export function useCategoryManager(collectionId: number, port: CategoryManagerPort, onClose: () => void) {
  const load = port.loadCategoriesForCollection;
  const fetch = useCallback(async (signal: AbortSignal) => {
    await load(collectionId, { signal, throwOnError: true });
    return true;
  }, [collectionId, load]);
  const resource = useAsyncData(fetch);
  const categories = port.categories.filter(category => category.collectionId === collectionId);
  const [editor, setEditor] = useState<Editor>({ type: 'tree' });
  const [dirty, setDirty] = useState(false);
  const [destination, setDestination] = useState<Destination | null>(null);
  const [operation, setOperation] = useState<ReturnType<typeof categoryOperation> | null>(null);
  const action = useAsyncAction();
  const saved = operation?.hasSaved ?? false;
  const locked = action.pending || saved;

  const navigate = (target: Destination) => {
    setDestination(null);
    setOperation(null);
    setDirty(false);
    setEditor({ type: 'tree' });
    if (target === 'close') onClose();
  };
  const leave = (target: Destination) => {
    if (action.pending) return;
    if (dirty || saved) setDestination(target);
    else navigate(target);
  };
  const execute = (command: CategoryCommand) => {
    if (saved) return;
    return action.run(async () => {
      const next = categoryOperation(port, collectionId, categories, command);
      setOperation(next);
      await next.run();
    }, 'Unable to save category changes', () => navigate('tree'));
  };
  return {
    categories, resource, editor, dirty, setDirty, destination, saved, locked, pending: action.pending,
    error: operation ? action.error : null,
    leave, cancelLeave: () => setDestination(null), confirmLeave: () => { if (destination) navigate(destination); },
    openQuick: () => { setOperation(null); setEditor({ type: 'quick' }); setDirty(false); },
    openForm: (category: Category | null, initialName = '') => { setOperation(null); setDirty(false); setEditor({ type: 'form', category, initialName }); },
    execute,
    retry: () => action.run(() => operation!.run(), 'Unable to finish category changes', () => navigate('tree')),
  };
}
