import { useRef, useState } from 'react';
import type { UpdateWorkspaceRequest } from '../../api/workspaces';
import type { WorkspaceMembership } from '../../utils/types';
import { isValidSlug, toSlug } from '../../utils/slugUtils';
import { useAsyncAction } from '../../utils/useAsyncAction';
import { getErrorMessage } from '../../utils/errorUtils';

export type SaveWorkspace = (id: number, request: UpdateWorkspaceRequest) => Promise<unknown>;
type Draft = { name: string; slug: string };
type Attempt = { saved: true; draft: Draft } | { saved: false; error: string };

/** A mounted editor retains its draft until it is saved or explicitly discarded. */
export function useWorkspaceDraft(workspace: WorkspaceMembership, saveWorkspace: SaveWorkspace, refresh: () => Promise<void>, onSaved: () => void) {
  const [initial, setInitial] = useState(() => ({ name: workspace.workspaceName, slug: workspace.slug || toSlug(workspace.workspaceName) }));
  const [draft, setDraft] = useState(initial);
  const attempt = useRef<Attempt | null>(null);
  const [reviewRequired, setReviewRequired] = useState(false);
  const action = useAsyncAction();
  const dirty = draft.name !== initial.name || draft.slug !== initial.slug;

  const save = () => action.run(async () => {
    if (!attempt.current) {
      const name = draft.name.trim();
      if (!name) throw new Error('Workspace name is required');
      const slug = draft.slug.trim();
      if (slug && !isValidSlug(slug)) {
        throw new Error('Slug must be 3-50 characters, lowercase letters, numbers, and hyphens only. Must start and end with a letter or number, with no consecutive hyphens.');
      }
      try {
        await saveWorkspace(workspace.workspaceId, { name, slug: slug || null });
        attempt.current = { saved: true, draft: { name, slug } };
      } catch (cause) {
        attempt.current = { saved: false, error: getErrorMessage(cause, 'Failed to save workspace') };
      }
      setReviewRequired(true);
    }
    // Even a lost write response may have committed. Reconcile session metadata
    // before permitting another edit; recovery only repeats this read.
    await refresh();
    return attempt.current;
  }, 'Unable to refresh workspace details', outcome => {
    attempt.current = null;
    setReviewRequired(false);
    if (!outcome.saved) throw new Error(outcome.error);
    setInitial(outcome.draft);
    setDraft(outcome.draft);
    onSaved();
  });

  return { draft, setDraft, dirty, save, reviewRequired, pending: action.pending, error: action.error };
}
