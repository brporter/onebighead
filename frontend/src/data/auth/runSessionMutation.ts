import type { SessionChangeKind, SessionChanges } from './SessionChanges';
import { getErrorMessage } from '../../utils/errorUtils';

export interface SessionMutationContext {
  changes: SessionChanges;
  refresh: () => Promise<void>;
  confirmDiscard: () => boolean;
}

/** Preserve typed command results while sharing protection and read-only recovery. */
export async function runSessionMutation<T>({ changes, kind, change, refresh, confirmDiscard, failure, cancelled }: SessionMutationContext & {
  kind: SessionChangeKind;
  change: () => Promise<T>;
  failure: string;
  cancelled: string;
}): Promise<T> {
  let result!: T;
  const success = await changes.run(kind, async () => {
    try { result = await change(); }
    catch (cause) { throw new Error(getErrorMessage(cause, failure)); }
  }, refresh, confirmDiscard);
  if (!success) throw new Error(changes.getSnapshot().error ?? cancelled);
  return result;
}
