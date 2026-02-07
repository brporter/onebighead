import { useState } from 'react';
import { DeletionStatsGrid, type DeletionStatsGridProps } from './DeletionStatsGrid';
import { DeletionBlockerReason, WorkspaceActionType, type UserBasicInfo } from '../../api/account';

export interface WorkspaceBlocker {
  workspaceId: number;
  workspaceName: string;
  reason: DeletionBlockerReason;
  users?: UserBasicInfo[];
  resolved?: boolean;
  action?: WorkspaceActionType;
  transferToUserId?: number;
}

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
  onExport?: () => Promise<void>;
  isExporting?: boolean;

  // Confirmation
  confirmationType: 'checkbox' | 'text-match';
  confirmationText?: string;

  // Blockers (for account deletion)
  blockers?: WorkspaceBlocker[];
  onResolveBlocker?: (workspaceId: number, action: WorkspaceActionType, userId?: number) => void;
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
  onExport,
  isExporting,
  confirmationType,
  confirmationText,
  blockers,
  onResolveBlocker,
}: DeletionConfirmationModalProps) {
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
    if (!canConfirm) return;

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

  const handleExport = async () => {
    if (!onExport) return;
    try {
      await onExport();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Export failed');
    }
  };

  const handleClose = () => {
    if (isDeleting) return;
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
                {blocker.users && blocker.users.length > 0 && (
                  <div className="deletion-modal__blocker-select">
                    <label className="deletion-modal__blocker-label">Transfer admin to:</label>
                    <select
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
                )}
              </>
            )}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="modal-overlay" onClick={handleClose}>
      <div className="modal deletion-modal" onClick={e => e.stopPropagation()}>
        <div className="modal__header">
          <h2 className="modal__title">{title}</h2>
          <button className="modal__close" onClick={handleClose} disabled={isDeleting}>
            &times;
          </button>
        </div>

        <div className="modal__body">
          {/* Warning banner */}
          <div className="deletion-modal__warning">
            <span className="deletion-modal__warning-icon">&#9888;</span>
            <div className="deletion-modal__warning-content">
              <strong>This action cannot be undone.</strong>
              {entityType === 'workspace' && (
                <p>Deleting "{entityName}" will permanently remove all collections, categories, items, and images.</p>
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
          {showExportOption && onExport && (
            <div className="deletion-modal__export">
              <p>Before deleting, you can export your data:</p>
              <button
                className="deletion-modal__export-button"
                onClick={handleExport}
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
                  <span>I understand that this action is permanent and cannot be undone.</span>
                </label>
              ) : (
                <div className="deletion-modal__text-confirm">
                  <label className="deletion-modal__text-label">
                    Type <strong>{confirmationText || entityName}</strong> to confirm:
                  </label>
                  <input
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
            <div className="deletion-modal__error">
              {error}
            </div>
          )}
        </div>

        <div className="modal__footer">
          <button
            className="modal__button modal__button--secondary"
            onClick={handleClose}
            disabled={isDeleting}
          >
            Cancel
          </button>
          <button
            className="modal__button modal__button--danger"
            onClick={handleConfirm}
            disabled={!canConfirm || isDeleting}
          >
            {isDeleting ? 'Deleting...' : `Delete ${entityType === 'workspace' ? 'Workspace' : 'Account'}`}
          </button>
        </div>
      </div>
    </div>
  );
}

export default DeletionConfirmationModal;
