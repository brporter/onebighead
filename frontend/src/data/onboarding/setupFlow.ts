import type { CompleteWelcomeRequest, CompleteWelcomeResponse } from '../../api/auth';
import type { SetupWorkspaceRequest, SetupWorkspaceResponse } from '../../api/workspaces';
import { ApiError } from '../../api/transport';
import type { SetupAttemptStore, SetupDraft } from './setupAttempt';
export type { SetupDraft } from './setupAttempt';

export type WorkspaceSetupResult = Pick<CompleteWelcomeResponse, 'workspaceId' | 'workspaceName' | 'collectionId' | 'collectionName'>;
export interface SetupFlow {
  readonly started: boolean;
  readonly draft?: SetupDraft;
  complete: (draft: SetupDraft) => Promise<WorkspaceSetupResult>;
  skip?: () => Promise<void>;
}
type RefreshSession = () => Promise<void>;

/** One wizard owns a flow and serializes its calls. Confirmed writes survive retries. */
export function createWorkspaceFlow(setup: (request: SetupWorkspaceRequest) => Promise<SetupWorkspaceResponse>, refresh: RefreshSession,
  store: SetupAttemptStore, requestId: () => string = () => crypto.randomUUID()): SetupFlow {
  let attempt = store.read();
  let result: WorkspaceSetupResult | undefined;
  return {
    get started() { return attempt !== undefined; },
    get draft() { return attempt?.draft; },
    async complete(draft) {
      if (!attempt) {
        const next = { requestId: requestId(), draft: { ...draft } };
        store.save(next);
        attempt = next;
      }
      if (!result) {
        try {
          result = await setup({ requestId: attempt.requestId, workspaceName: attempt.draft.workspaceName,
            collectionName: attempt.draft.collectionName || undefined,
            collectionDescription: attempt.draft.description || undefined, themeId: attempt.draft.themeId });
        } catch (error) {
          // Validation rejects creation; Gone confirms a prior creation is no
          // longer accessible. Uncertain failures retain the original identity.
          if (error instanceof ApiError && (error.status === 400 || error.status === 410)) {
            store.clear(attempt.requestId);
            attempt = undefined;
          }
          throw error;
        }
      }
      // Setup already activates the workspace and sets its session cookie.
      await refresh();
      store.clear(attempt.requestId);
      return result;
    },
  };
}

export function createWelcomeFlow(
  completeWelcome: (request: CompleteWelcomeRequest) => Promise<CompleteWelcomeResponse>,
  refresh: RefreshSession,
): SetupFlow {
  let workspace: CompleteWelcomeResponse | undefined;
  return {
    get started() { return workspace !== undefined; },
    async complete(draft) {
      // One server transaction owns the collection and welcome completion.
      // A lost response can be retried, including by a remounted wizard.
      workspace ??= await completeWelcome({ workspaceName: draft.workspaceName,
        collection: { name: draft.collectionName, description: draft.description, themeId: draft.themeId } });
      await refresh();
      return workspace;
    },
    async skip() {
      workspace ??= await completeWelcome({});
      await refresh();
    },
  };
}
