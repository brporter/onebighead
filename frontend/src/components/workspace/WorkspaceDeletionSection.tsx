import { useCallback, useState } from 'react';
import { DeletionConfirmationModal } from '../common/DeletionConfirmationModal';
import { ModalDialog } from '../common/ModalDialog';
import { ContentState } from '../common/ContentState';
import { SessionChangeFeedback } from '../common/SessionChangeFeedback';
import { workspacesApi, exportApi } from '../../api';
import type { WorkspaceMembership } from '../../utils/types';
import { useAsyncData } from '../../utils/useAsyncData';
import { saveDownload } from '../../utils/saveDownload';
import { removeWorkspace } from '../../data/workspaces/removeWorkspace';
import { useSessionChanges } from '../../data/auth/useSessionChanges';
import { useEditorStatus, type EditorStatusListener } from '../../data/shared/useEditorStatus';

interface WorkspaceDeletionSectionProps {
  workspace: WorkspaceMembership;
  exportAvailable: boolean;
  onClose: () => void;
  refresh: () => Promise<void>;
  onStatusChange?: EditorStatusListener;
}

/** One mounted confirmation owns its statistics, export and session recovery. */
export function WorkspaceDeletionSection({ workspace, exportAvailable, onClose, refresh, onStatusChange }: WorkspaceDeletionSectionProps) {
  const fetchStats = useCallback((signal: AbortSignal) => workspacesApi.getStats(workspace.workspaceId, { signal }), [workspace.workspaceId]);
  const stats = useAsyncData(fetchStats);
  const [exporting, setExporting] = useState(false);
  const { changes, state, managed } = useSessionChanges();
  const busy = state.pending || state.recovery || state.leaving;
  useEditorStatus(false, stats.loading || exporting || busy, onStatusChange);

  async function handleExport() {
    setExporting(true);
    try { saveDownload(await exportApi.downloadExport()); }
    finally { setExporting(false); }
  }

  async function confirm() {
    const outcome = await removeWorkspace(workspace.workspaceId, workspacesApi, {
      changes, refresh, confirmDiscard: () => window.confirm('You have unsaved changes. Discard them?'),
    });
    if (outcome === 'signed-out') window.location.href = '/';
  }

  const title = `Delete "${workspace.workspaceName}"`;
  return <>
    {stats.data ? <DeletionConfirmationModal
      isOpen onClose={onClose} onConfirm={confirm} title={title} entityType="workspace" entityName={workspace.workspaceName}
      stats={{ collections: stats.data.collectionCount, categories: stats.data.categoryCount, items: stats.data.itemCount, images: stats.data.imageCount, users: stats.data.userCount }}
      showExportOption={exportAvailable}
      exportUnavailableReason={exportAvailable ? undefined : 'To back up this workspace before deleting it, cancel and switch to it first. Data Export downloads the active workspace.'}
      onExport={handleExport} isExporting={exporting} confirmationType="checkbox"
      errorAction={{ label: 'Review deletion information', onClick: stats.retry }}
    /> : <ModalDialog label={title} onClose={onClose}>
      <section className="modal">
        <div className="modal__header"><h2 className="modal__title">{title}</h2></div>
        <div className="modal__body">{stats.error
          ? <ContentState kind="error" title="Unable to load deletion information" action={<button type="button" className="content-state__button" onClick={stats.retry}>Try again</button>}>{stats.error}</ContentState>
          : <ContentState kind="loading" title="Loading deletion information…" />}</div>
        <div className="modal__footer"><button type="button" className="modal__button modal__button--secondary" onClick={onClose}>Cancel</button></div>
      </section>
    </ModalDialog>}
    {!managed && <SessionChangeFeedback changes={changes} />}
  </>;
}

export default WorkspaceDeletionSection;
