import { useState, useEffect, useRef, useCallback } from 'react';
import { bulkUpdatesApi } from '../../api/bulkUpdates';
import type { BulkUpdateJobResponse, EnqueueBulkUpdateRequest } from '../../api/bulkUpdates';
import '../../styles/components/BulkUpdateModal.css';

type ModalPhase = 'prompt' | 'progress' | 'complete';

interface ScopeOption {
  scope: string;
  label: string;
  count: number;
  templateKey?: string;
  categoryId?: number;
  collectionId?: number;
}

interface BulkUpdateModalProps {
  isOpen: boolean;
  onClose: () => void;
  onComplete?: () => void;
  scopeOptions: ScopeOption[];
  oldProperties: { category: string; name: string }[];
  newProperties: { category: string; name: string }[];
  renameMappings?: { oldCategory: string; oldName: string; newCategory: string; newName: string }[];
  excludeItemId?: number;
}

function BulkUpdateModal({
  isOpen,
  onClose,
  onComplete,
  scopeOptions,
  oldProperties,
  newProperties,
  renameMappings,
  excludeItemId,
}: BulkUpdateModalProps) {
  const [phase, setPhase] = useState<ModalPhase>('prompt');
  const [selectedScope, setSelectedScope] = useState(0);
  const [job, setJob] = useState<BulkUpdateJobResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const dialogRef = useRef<HTMLDialogElement>(null);
  const pollRef = useRef<number | null>(null);

  // Control dialog open/close
  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;

    if (isOpen) {
      setPhase('prompt');
      setJob(null);
      setError(null);
      setSelectedScope(0);
      dialog.showModal();
    } else {
      dialog.close();
    }
  }, [isOpen]);

  // Handle native dialog close
  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;

    const handleClose = () => {
      stopPolling();
      onClose();
    };

    dialog.addEventListener('close', handleClose);
    return () => dialog.removeEventListener('close', handleClose);
  }, [onClose]);

  // Cleanup polling on unmount
  useEffect(() => {
    return () => stopPolling();
  }, []);

  const stopPolling = () => {
    if (pollRef.current !== null) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  };

  const startPolling = useCallback((jobId: string) => {
    stopPolling();
    pollRef.current = window.setInterval(async () => {
      try {
        const status = await bulkUpdatesApi.getStatus(jobId);
        setJob(status);

        if (status.status === 'Completed' || status.status === 'Failed') {
          stopPolling();
          setPhase('complete');
        }
      } catch {
        stopPolling();
        setError('Failed to check update status');
        setPhase('complete');
      }
    }, 500);
  }, []);

  const handleApply = async () => {
    const option = scopeOptions[selectedScope];
    if (!option) return;

    setError(null);

    const request: EnqueueBulkUpdateRequest = {
      scope: option.scope,
      templateKey: option.templateKey,
      categoryId: option.categoryId,
      collectionId: option.collectionId,
      excludeItemId,
      oldProperties: oldProperties.map(p => ({ category: p.category, name: p.name })),
      newProperties: newProperties.map(p => ({ category: p.category, name: p.name })),
      renameMappings: renameMappings?.map(m => ({
        oldCategory: m.oldCategory,
        oldName: m.oldName,
        newCategory: m.newCategory,
        newName: m.newName,
      })),
    };

    try {
      const result = await bulkUpdatesApi.enqueue(request);
      setJob(result);
      setPhase('progress');
      startPolling(result.jobId);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start bulk update');
    }
  };

  const handleClose = () => {
    stopPolling();
    if (phase === 'complete') {
      onComplete?.();
    }
    onClose();
  };

  const handleBackdropClick = (e: React.MouseEvent<HTMLDialogElement>) => {
    if (e.target === e.currentTarget && phase !== 'progress') {
      handleClose();
    }
  };

  const progressPercent = job && job.totalItems > 0
    ? Math.round((job.processedItems / job.totalItems) * 100)
    : 0;

  return (
    <dialog ref={dialogRef} className="modal-dialog" onClick={handleBackdropClick}>
      <div className="modal bulk-update-modal">
        <div className="modal__header">
          <h3 className="modal__title">
            {phase === 'prompt' && 'Apply Property Changes'}
            {phase === 'progress' && 'Updating Items...'}
            {phase === 'complete' && 'Update Complete'}
          </h3>
          {phase !== 'progress' && (
            <button className="modal__close" onClick={handleClose} type="button">
              &times;
            </button>
          )}
        </div>

        <div className="modal__body">
          {phase === 'prompt' && (
            <>
              <p className="modal__info">
                Apply these property changes to other existing items?
              </p>

              {scopeOptions.length === 1 ? (
                <p className="bulk-update-modal__count">
                  {scopeOptions[0].count} {scopeOptions[0].count === 1 ? 'item' : 'items'} {scopeOptions[0].label}
                </p>
              ) : (
                <div className="bulk-update-modal__scopes">
                  {scopeOptions.map((option, index) => (
                    <label key={option.scope + (option.categoryId ?? '') + (option.collectionId ?? '')} className="bulk-update-modal__scope">
                      <input
                        type="radio"
                        name="bulkUpdateScope"
                        checked={selectedScope === index}
                        onChange={() => setSelectedScope(index)}
                      />
                      <span>{option.count} {option.count === 1 ? 'item' : 'items'} {option.label}</span>
                    </label>
                  ))}
                </div>
              )}

              {error && <p className="modal__error">{error}</p>}

              <div className="modal__actions">
                <button
                  className="modal__button modal__button--primary"
                  onClick={handleApply}
                  disabled={scopeOptions[selectedScope]?.count === 0}
                  type="button"
                >
                  {scopeOptions.length === 1 ? 'Apply to All' : 'Apply'}
                </button>
                <button
                  className="modal__button modal__button--secondary"
                  onClick={handleClose}
                  type="button"
                >
                  Skip
                </button>
              </div>
            </>
          )}

          {phase === 'progress' && job && (
            <div className="bulk-update-modal__progress">
              <div className="bulk-update-modal__bar-container">
                <div
                  className="bulk-update-modal__bar-fill"
                  style={{ width: `${progressPercent}%` }}
                />
              </div>
              <p className="bulk-update-modal__progress-text">
                {job.processedItems + job.failedItems} / {job.totalItems} items
              </p>
            </div>
          )}

          {phase === 'complete' && (
            <>
              {job?.status === 'Completed' && (
                <p className="bulk-update-modal__summary">
                  Updated {job.processedItems} {job.processedItems === 1 ? 'item' : 'items'}.
                  {job.failedItems > 0 && ` (${job.failedItems} skipped)`}
                </p>
              )}
              {job?.status === 'Failed' && (
                <p className="modal__error">
                  Update failed: {job.errorMessage ?? 'Unknown error'}
                </p>
              )}
              {error && <p className="modal__error">{error}</p>}

              <div className="modal__actions">
                <button
                  className="modal__button modal__button--primary"
                  onClick={handleClose}
                  type="button"
                >
                  Close
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </dialog>
  );
}

export { BulkUpdateModal };
export type { ScopeOption };
