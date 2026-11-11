import '../../styles/components/DeletionConfirmationModal.css';
import { ModalDialog } from './ModalDialog';
import { useId, useState } from 'react';
import { DeletionStatsGrid, type DeletionStatsGridProps } from './DeletionStatsGrid';
import { DeletionBlockerReason, WorkspaceActionType } from '../../api/account';
import type { AccountDeletionBlocker as WorkspaceBlocker } from '../../data/account/deletionPlan';
export type { AccountDeletionBlocker as WorkspaceBlocker } from '../../data/account/deletionPlan';

export interface DeletionConfirmationModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => Promise<void>;

  // Content
  title: string;
  entityType: 'workspace' | 'account';
  entityName: string;

  // Statistics (optional)
  stats?: DeletionStatsGridProps;

  // Export
  showExportOption?: boolean;
  exportUnavailableReason?: string;
  onExport?: () => Promise<void>;
  isExporting?: boolean;

  // Confirmation
  confirmationType: 'checkbox' | 'text-match';
  confirmationText?: string;

  // Blockers (for account deletion)
  blockers?: WorkspaceBlocker[];
  onResolveBlocker?: (workspaceId: number, action: WorkspaceActionType, userId?: number) => void;
  errorAction?: { label: string; onClick: () => void };
}

export function DeletionConfirmationModal({
  isOpen,
  onClose,
  onConfirm,
  title,
  entityType,
  entityName,
  stats,
  showExportOption,
  exportUnavailableReason,
  onExport,
  isExporting,
  confirmationType,
  confirmationText,
  blockers,
  onResolveBlocker,
  errorAction,
}: DeletionConfirmationModalProps) {
  const confirmationId = useId();
  const [isConfirmed, setIsConfirmed] = useState(false);
  const [confirmInput, setConfirmInput] = useState('');
  const [isDeleting, setIsDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const allBlockersResolved = !blockers || blockers.every(b => b.resolved);

  const isTextConfirmationValid = confirmationType === 'text-match'
    ? confirmInput.toLowerCase() === (confirmationText?.toLowerCase() || entityName.toLowerCase())
    : true;

  const canConfirm =
    allBlockersResolved &&
    (confirmationType === 'checkbox' ? isConfirmed : isTextConfirmationValid);

  const handleConfirm = async () => {
    if (!canConfirm || isDeleting || isExporting) return;

    setIsDeleting(true);
    setError(null);

    try {
      await onConfirm();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Deletion failed');
      setIsDeleting(false);
    }
  };

  const handleExport = async (exportData: () => Promise<void>) => {
    try {
      await exportData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Export failed');
    }
  };

  const handleClose = () => {
    if (isDeleting || isExporting) return;
    setIsConfirmed(false);
    setConfirmInput('');
    setError(null);
    onClose();
  };

  const renderBlocker = (blocker: WorkspaceBlocker) => {
    const isResolved = blocker.resolved;

    return (
      <div key={blocker.workspaceId} className={`deletion-modal__blocker ${isResolved ? 'deletion-modal__blocker--resolved' : ''}`}>
        <div className="deletion-modal__blocker-header">
          <span className="deletion-modal__blocker-name">{blocker.workspaceName}</span>
          {isResolved && <span className="deletion-modal__blocker-status">Resolved</span>}
        </div>

        {!isResolved && (
          <div className="deletion-modal__blocker-content">
            {blocker.reason === DeletionBlockerReason.SoleUser && (
              <>
                <p className="deletion-modal__blocker-description">
                  You are the only member of this workspace. It will be deleted when you delete your account.
                </p>
                <button
                  type="button"
                  className="deletion-modal__blocker-action"
                  onClick={() => onResolveBlocker?.(blocker.workspaceId, WorkspaceActionType.Delete)}
                >
                  Confirm deletion of workspace
                </button>
              </>
            )}

            {blocker.reason === DeletionBlockerReason.SoleAdmin && (
              <>
                <p className="deletion-modal__blocker-description">
                  You are the only admin. Transfer admin role to another user before deleting your account.
                </p>
                {blocker.users && blocker.users.length > 0 ? (
                  <div className="deletion-modal__blocker-select">
                    <label htmlFor={`${confirmationId}-${blocker.workspaceId}`} className="deletion-modal__blocker-label">Transfer admin to:</label>
                    <select
                      id={`${confirmationId}-${blocker.workspaceId}`}
                      className="deletion-modal__blocker-dropdown"
                      value={blocker.transferToUserId || ''}
                      onChange={(e) => {
                        const userId = parseInt(e.target.value);
                        if (userId) {
                          onResolveBlocker?.(blocker.workspaceId, WorkspaceActionType.Transfer, userId);
                        }
                      }}
                    >
                      <option value="">Select a user...</option>
                      {blocker.users.map(user => (
                        <option key={user.userId} value={user.userId}>
                          {user.email}
                        </option>
                      ))}
                    </select>
                  </div>
                ) : (
                  <p className="deletion-modal__blocker-description">
                    No active member can receive the admin role. Close this dialog and resolve membership or delete this workspace in Settings before deleting your account.
                  </p>
                )}
              </>
            )}
          </div>
        )}
      </div>
    );
  };

  return (
    <ModalDialog label={title} onClose={handleClose}>
      <form className="modal deletion-modal" aria-label="Confirm deletion" onSubmit={event => { event.preventDefault(); void handleConfirm(); }}>
        <div className="modal__header">
          <h2 className="modal__title">{title}</h2>
          <button type="button" className="modal__close" onClick={handleClose} disabled={isDeleting || isExporting} aria-label="Close">
            &times;
          </button>
        </div>

        <div className="modal__body">
          {/* Warning banner */}
          <div className="deletion-modal__warning">
            <span className="deletion-modal__warning-icon">&#9888;</span>
            <div className="deletion-modal__warning-content">
              <strong>{entityType === 'account' ? 'This action cannot be undone.' : 'This workspace will be deleted.'}</strong>
              {entityType === 'workspace' && (
                <p>Deleting "{entityName}" removes access to its collections, categories, items, and images. Restore it from My Workspaces before its recovery period ends.</p>
              )}
              {entityType === 'account' && (
                <p>Deleting your account will permanently remove your profile and access to all workspaces.</p>
              )}
            </div>
          </div>

          {/* Statistics */}
          {stats && (
            <div className="deletion-modal__stats">
              <h3 className="deletion-modal__stats-title">Data to be deleted:</h3>
              <DeletionStatsGrid {...stats} />
            </div>
          )}

          {/* Export option */}
          {exportUnavailableReason && <p className="deletion-modal__export">{exportUnavailableReason}</p>}
          {showExportOption && onExport && (
            <div className="deletion-modal__export">
              <p>Before deleting, you can export your data:</p>
              <button
                type="button"
                className="deletion-modal__export-button"
                onClick={() => { void handleExport(onExport); }}
                disabled={isExporting || isDeleting}
              >
                {isExporting ? 'Exporting...' : 'Download Export'}
              </button>
            </div>
          )}

          {/* Blockers */}
          {blockers && blockers.length > 0 && (
            <div className="deletion-modal__blockers">
              <h3 className="deletion-modal__blockers-title">
                Resolve the following before continuing:
              </h3>
              {blockers.map(renderBlocker)}
            </div>
          )}

          {/* Confirmation */}
          {allBlockersResolved && (
            <div className="deletion-modal__confirmation">
              {confirmationType === 'checkbox' ? (
                <label className="deletion-modal__checkbox-label">
                  <input
                    type="checkbox"
                    checked={isConfirmed}
                    onChange={(e) => setIsConfirmed(e.target.checked)}
                    disabled={isDeleting}
                  />
                  <span>{entityType === 'workspace' ? 'I understand that this workspace will be deleted.' : 'I understand that this action is permanent and cannot be undone.'}</span>
                </label>
              ) : (
                <div className="deletion-modal__text-confirm">
                  <label htmlFor={confirmationId} className="deletion-modal__text-label">
                    Type <strong>{confirmationText || entityName}</strong> to confirm:
                  </label>
                  <input
                    id={confirmationId}
                    type="text"
                    className="deletion-modal__text-input"
                    value={confirmInput}
                    onChange={(e) => setConfirmInput(e.target.value)}
                    placeholder={confirmationText || entityName}
                    disabled={isDeleting}
                    autoComplete="off"
                  />
                </div>
              )}
            </div>
          )}

          {/* Error */}
          {error && (
            <div className="deletion-modal__error" role="alert">
              {error}
              {errorAction && <button type="button" className="deletion-modal__blocker-action" onClick={errorAction.onClick}
                disabled={isDeleting || isExporting}>{errorAction.label}</button>}
            </div>
          )}
        </div>

        <div className="modal__footer">
          <button
            type="button"
            className="modal__button modal__button--secondary"
            onClick={handleClose}
            disabled={isDeleting || isExporting}
          >
            Cancel
          </button>
          <button
            type="submit"
            className="modal__button modal__button--danger"
            disabled={!canConfirm || isDeleting || isExporting}
          >
            {isDeleting ? 'Deleting...' : `Delete ${entityType === 'workspace' ? 'Workspace' : 'Account'}`}
          </button>
        </div>
      </form>
    </ModalDialog>
  );
}

export default DeletionConfirmationModal;
