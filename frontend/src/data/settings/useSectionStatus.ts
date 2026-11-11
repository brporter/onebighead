import { useCallback, useState } from 'react';
import type { EditorStatus } from '../shared/useEditorStatus';

/** A previous section cannot replace the new section's navigation constraints. */
export function useSectionStatus(section: string) {
  const [status, setStatus] = useState({ section, dirty: false, pending: false });
  if (status.section !== section) setStatus({ section, dirty: false, pending: false });
  const report = useCallback((next: EditorStatus) => {
    setStatus(previous => previous.section === section ? { section, ...next } : previous);
  }, [section]);
  return { dirty: status.dirty, pending: status.pending, report };
}
