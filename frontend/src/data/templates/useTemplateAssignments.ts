import { useEffect, useRef, useState } from 'react';
import { useAsyncAction } from '../../utils/useAsyncAction';

export interface TemplateAssignmentsPort {
  associateTemplateWithCollection: (collectionId: number, templateId: number) => Promise<void>;
  disassociateTemplateFromCollection: (collectionId: number, templateId: number) => Promise<void>;
}

/** A mounted editor owns one collection. Confirmed operations are never repeated on retry. */
export function useTemplateAssignments(collectionId: number, initialIds: number[], port: TemplateAssignmentsPort) {
  const [selected, setSelected] = useState(new Set(initialIds));
  const [committed, setCommitted] = useState(new Set(initialIds));
  const action = useAsyncAction();
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const dirty = selected.size !== committed.size || [...selected].some(id => !committed.has(id));

  const save = () => action.run(async () => {
    const changes = [
      ...[...selected].filter(id => !committed.has(id)).map(id => ({ id, selected: true })),
      ...[...committed].filter(id => !selected.has(id)).map(id => ({ id, selected: false })),
    ];
    const results = await Promise.allSettled(changes.map(async change => {
      if (change.selected) await port.associateTemplateWithCollection(collectionId, change.id);
      else await port.disassociateTemplateFromCollection(collectionId, change.id);
      return change;
    }));
    if (!mounted.current) return;
    setCommitted(previous => {
      const next = new Set(previous);
      for (const result of results) if (result.status === 'fulfilled') {
        if (result.value.selected) next.add(result.value.id); else next.delete(result.value.id);
      }
      return next;
    });
    const failure = results.find(result => result.status === 'rejected');
    if (failure) throw failure.reason;
  }, 'Failed to save changes');

  return { selectedIds: [...selected], select: (ids: number[]) => setSelected(new Set(ids)), dirty,
    save, saving: action.pending, error: action.error };
}
