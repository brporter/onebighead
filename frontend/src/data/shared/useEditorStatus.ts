import { useLayoutEffect } from 'react';
import { useSessionProtection } from '../auth/useSessionChanges';

export interface EditorStatus { dirty: boolean; pending: boolean }
export type EditorStatusListener = (status: EditorStatus) => void;

/** Commit navigation constraints before the corresponding controls are painted. */
export function useEditorStatus(dirty: boolean, pending: boolean, onChange?: EditorStatusListener) {
  useSessionProtection(dirty, pending);
  useLayoutEffect(() => { onChange?.({ dirty, pending }); }, [dirty, pending, onChange]);
  useLayoutEffect(() => () => { onChange?.({ dirty: false, pending: false }); }, [onChange]);
}
