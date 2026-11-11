import type { SetupAttempt, SetupAttemptStore } from './setupAttempt';

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const invalid = () => new Error('Saved workspace setup could not be read. Keep this tab open and try again before creating another workspace.');

function parse(text: string): SetupAttempt {
  let value: unknown;
  try { value = JSON.parse(text); } catch { throw invalid(); }
  if (typeof value !== 'object' || value === null) throw invalid();
  const record = value as Record<string, unknown>;
  if (record.version !== 1 || typeof record.requestId !== 'string' || !uuid.test(record.requestId)) throw invalid();
  if (typeof record.draft !== 'object' || record.draft === null) throw invalid();
  const draft = record.draft as Record<string, unknown>;
  if (['workspaceName', 'collectionName', 'description'].some(field => typeof draft[field] !== 'string') ||
    !Number.isSafeInteger(draft.themeId) || (draft.themeId as number) <= 0) throw invalid();
  return { requestId: record.requestId, draft: draft as unknown as SetupAttempt['draft'] };
}

/** Tab-local, account-scoped recovery survives reloads without affecting another signed-in account. */
export function setupAttemptStorage(userId: number, storage: () => Pick<Storage, 'getItem' | 'setItem' | 'removeItem'> = () => window.sessionStorage): SetupAttemptStore {
  const key = `workspace-setup:${userId}`;
  const read = () => {
    const value = storage().getItem(key);
    return value === null ? undefined : parse(value);
  };
  return {
    read,
    save(attempt) {
      const current = read();
      if (current && current.requestId !== attempt.requestId)
        throw new Error('Another workspace setup is awaiting recovery. Close and reopen setup to continue it.');
      storage().setItem(key, JSON.stringify({ version: 1, ...attempt }));
    },
    clear(requestId) {
      if (read()?.requestId === requestId) storage().removeItem(key);
    },
  };
}
