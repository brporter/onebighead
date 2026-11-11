import { useState } from 'react';
import { bulkUpdatesApi } from '../../api/bulkUpdates';
import { isBulkUpdateActive, useBulkUpdateMonitor } from '../../data/bulkUpdates/useBulkUpdateMonitor';
import { useBulkUpdateSubmission } from '../../data/bulkUpdates/useBulkUpdateSubmission';
import { BulkUpdateStatus } from './BulkUpdateStatus';
import { ModalDialog } from './ModalDialog';
import type { ScopeOption } from '../../data/bulkUpdates/types';
import { useEditorStatus, type EditorStatusListener } from '../../data/shared/useEditorStatus';
import '../../styles/components/BulkUpdateModal.css';

interface BulkUpdateModalProps {
  isOpen: boolean;
  onClose: () => void;
  onComplete?: () => void;
  onStatusChange?: EditorStatusListener;
  scopeOptions: ScopeOption[];
  oldProperties: { category: string; name: string }[];
  newProperties: { category: string; name: string }[];
  renameMappings?: { oldCategory: string; oldName: string; newCategory: string; newName: string }[];
  excludeItemId?: number;
}

/** Closing unmounts the workflow, resetting selection and cancelling pending work. */
function BulkUpdateModal(props: BulkUpdateModalProps) {
  return props.isOpen ? <BulkUpdateDialog {...props} /> : null;
}

function BulkUpdateDialog({ onClose, onComplete, onStatusChange, scopeOptions, oldProperties, newProperties, renameMappings, excludeItemId }: BulkUpdateModalProps) {
  const [selectedScope, setSelectedScope] = useState(0);
  const submission = useBulkUpdateSubmission(bulkUpdatesApi);
  const monitor = useBulkUpdateMonitor(submission.job, bulkUpdatesApi);
  const inProgress = submission.submitting || (monitor.job !== null && isBulkUpdateActive(monitor.job) && !monitor.error);
  const hasJob = monitor.job !== null;
  useEditorStatus(false, inProgress, onStatusChange);

  function handleApply() {
    const option = scopeOptions[selectedScope];
    void submission.submit({
      scope: option.scope, templateKey: option.templateKey, categoryId: option.categoryId,
      collectionId: option.collectionId, excludeItemId, oldProperties, newProperties, renameMappings,
    });
  }

  function handleClose() {
    if (inProgress) return;
    if (hasJob) onComplete?.();
    onClose();
  }

  const title = !hasJob ? 'Apply Property Changes' : inProgress ? 'Updating Items…' :
    monitor.error ? 'Update status unavailable' : monitor.job!.status === 'Failed' ? 'Update failed' : 'Update complete';

  return <ModalDialog isOpen onClose={handleClose} label="Bulk property update">
    <div className="modal bulk-update-modal" aria-busy={submission.submitting}>
      <div className="modal__header">
        <h3 className="modal__title">{title}</h3>
        {!inProgress && <button className="modal__close" onClick={handleClose} type="button" aria-label="Close bulk update">&times;</button>}
      </div>
      <div className="modal__body">
        {!hasJob ? <>
          <p className="modal__info">Apply these property changes to other existing items?</p>
          {scopeOptions.length === 1 ? <p className="bulk-update-modal__count">
            {scopeOptions[0].count} {scopeOptions[0].count === 1 ? 'item' : 'items'} {scopeOptions[0].label}
          </p> : <div className="bulk-update-modal__scopes">
            {scopeOptions.map((option, index) => <label key={index} className="bulk-update-modal__scope">
              <input type="radio" name="bulkUpdateScope" checked={selectedScope === index}
                disabled={submission.submitting} onChange={() => setSelectedScope(index)} />
              <span>{option.count} {option.count === 1 ? 'item' : 'items'} {option.label}</span>
            </label>)}
          </div>}
          {submission.error && <p className="modal__error" role="alert">{submission.error}</p>}
          <div className="modal__actions">
            <button className="modal__button modal__button--primary" onClick={handleApply}
              disabled={submission.submitting || !scopeOptions[selectedScope]?.count} type="button">
              {submission.submitting ? 'Starting update…' : scopeOptions.length === 1 ? 'Apply to All' : 'Apply'}
            </button>
            <button className="modal__button modal__button--secondary" onClick={handleClose} disabled={submission.submitting} type="button">Skip</button>
          </div>
        </> : <>
          <BulkUpdateStatus job={monitor.job} error={monitor.error} onRetry={monitor.retry} />
          {!inProgress && <div className="modal__actions">
            <button className="modal__button modal__button--primary" onClick={handleClose} type="button">Close</button>
          </div>}
        </>}
      </div>
    </div>
  </ModalDialog>;
}

export { BulkUpdateModal };
export type { ScopeOption };
