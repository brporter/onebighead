import type { publishManagerApi } from '../../api/publishManager';
import type { ExecuteResponse, PublishIntent, PublishRequirement, PublishResolution } from '../../utils/types';
import { getErrorMessage } from '../../utils/errorUtils';
import { resolveRequirements, type PublicationDraft } from './publicationRequirements';

export interface PublicationRequest extends PublishIntent { requestId: number; workspaceId: number }
export type PublicationGateway = Pick<typeof publishManagerApi, 'preflight' | 'execute'>;
export type PublicationPhase = 'checking' | 'review' | 'saving' | 'refreshing' | 'check-error' | 'execute-error' | 'refresh-error' | 'complete';
export interface PublicationState {
  phase: PublicationPhase;
  requirements: PublishRequirement[];
  draft: PublicationDraft;
  error: string | null;
  saved: ExecuteResponse | null;
}
export interface PublicationSessionOptions {
  request: PublicationRequest;
  gateway: PublicationGateway;
  refresh: (response: ExecuteResponse, signal: AbortSignal) => Promise<void>;
  complete: (response: ExecuteResponse) => void;
  dismiss: () => void;
}

/** One request owns preflight, consent, execution and refresh. Confirmed writes are never replayed. */
export function createPublicationSession({ request, gateway, refresh, complete, dismiss }: PublicationSessionOptions) {
  const initial = (): PublicationState => ({ phase: 'checking', requirements: [], draft: { slug: '', acknowledged: new Set() }, error: null, saved: null });
  let state = initial();
  let controller = new AbortController();
  const listeners = new Set<() => void>();
  const update = (patch: Partial<PublicationState>) => { state = { ...state, ...patch }; listeners.forEach(listener => listener()); };

  async function run(work: (signal: AbortSignal) => Promise<void>) {
    const active = controller;
    if (active.signal.aborted) return;
    await work(active.signal);
  }

  function review(requirements: PublishRequirement[], error: string | null = null) {
    update({ phase: 'review', requirements, error, draft: { ...state.draft, acknowledged: new Set() } });
  }

  async function refreshSaved(response: ExecuteResponse, signal: AbortSignal) {
    update({ phase: 'refreshing', saved: response, error: null });
    try {
      await refresh(response, signal);
      if (signal.aborted) return;
      update({ phase: 'complete' });
      complete(response);
    } catch (cause) {
      if (!signal.aborted) update({ phase: 'refresh-error', error: getErrorMessage(cause, 'Could not refresh the updated data.') });
    }
  }

  async function execute(resolutions: PublishResolution[], signal: AbortSignal) {
    update({ phase: 'saving', error: null });
    try {
      const response = await gateway.execute(request.workspaceId, { action: request.action, entities: request.entities, resolutions }, { signal });
      if (signal.aborted) return;
      if (!response.success) {
        const error = response.error ?? 'Could not update visibility.';
        if (response.requirements?.length) review(response.requirements, error);
        else update({ phase: 'execute-error', error });
        return;
      }
      await refreshSaved(response, signal);
    } catch (cause) {
      if (!signal.aborted) update({ phase: 'execute-error', error: getErrorMessage(cause, 'Could not update visibility.') });
    }
  }

  async function check(signal: AbortSignal) {
    update({ phase: 'checking', error: null });
    try {
      const response = await gateway.preflight(request.workspaceId, request.action, request.entities, { signal });
      if (signal.aborted) return;
      if (response.requirements.length > 0) review(response.requirements);
      else if (response.ready) await execute([], signal);
      else update({ phase: 'check-error', error: 'The visibility check returned no requirements. Check again to continue.' });
    } catch (cause) {
      if (!signal.aborted) update({ phase: 'check-error', error: getErrorMessage(cause, 'Could not check visibility requirements.') });
    }
  }

  return {
    getSnapshot: () => state,
    subscribe(listener: () => void) { listeners.add(listener); return () => { listeners.delete(listener); }; },
    start() {
      controller.abort();
      const active = new AbortController();
      controller = active;
      state = initial();
      // StrictMode cleanup can cancel the first mount before it starts network work.
      void Promise.resolve().then(() => { if (!active.signal.aborted) void run(check); });
    },
    stop() { controller.abort(); },
    cancel() {
      if (state.phase === 'saving' || state.phase === 'refreshing' || state.phase === 'complete' || controller.signal.aborted) return;
      controller.abort();
      dismiss();
    },
    setSlug(slug: string) {
      if (controller.signal.aborted || state.phase !== 'review') return;
      update({ draft: { ...state.draft, slug } });
    },
    toggle(key: string) {
      if (controller.signal.aborted || state.phase !== 'review') return;
      const acknowledged = new Set(state.draft.acknowledged);
      if (acknowledged.has(key)) acknowledged.delete(key); else acknowledged.add(key);
      update({ draft: { ...state.draft, acknowledged } });
    },
    submit() {
      if (state.phase !== 'review') return Promise.resolve();
      const resolutions = resolveRequirements(state.requirements, state.draft);
      return resolutions === null ? Promise.resolve() : run(signal => execute(resolutions, signal));
    },
    retry() {
      if (!['check-error', 'execute-error', 'refresh-error'].includes(state.phase)) return Promise.resolve();
      if (state.saved) return run(signal => refreshSaved(state.saved!, signal));
      return run(check);
    },
  };
}
