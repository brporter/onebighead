import React, { useState, useEffect, useRef } from 'react';
import type { WorkspaceMembership } from '../../utils/types';
import { workspacesApi } from '../../api';

interface WorkspaceEditModalProps {
  workspace: WorkspaceMembership | null;
  isOpen: boolean;
  onClose: () => void;
  onSaved?: () => void;
}

function WorkspaceEditModal({ workspace, isOpen, onClose, onSaved }: WorkspaceEditModalProps) {
  const [name, setName] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const dialogRef = useRef<HTMLDialogElement>(null);

  // Control dialog open/close
  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;

    if (isOpen) {
      dialog.showModal();
    } else {
      dialog.close();
    }
  }, [isOpen]);

  // Handle native dialog close (e.g., Escape key)
  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;

    const handleClose = () => {
      onClose();
    };

    dialog.addEventListener('close', handleClose);
    return () => dialog.removeEventListener('close', handleClose);
  }, [onClose]);

  // Reset form when modal opens or workspace changes
  useEffect(() => {
    if (isOpen && workspace) {
      setName(workspace.workspaceName);
      setError(null);
    }
  }, [isOpen, workspace]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const trimmedName = name.trim();
    if (!trimmedName) {
      setError('Workspace name is required');
      return;
    }

    if (!workspace) return;

    setIsSubmitting(true);
    setError(null);

    try {
      await workspacesApi.update(workspace.workspaceId, { name: trimmedName });
      onSaved?.();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleBackdropClick = (e: React.MouseEvent<HTMLDialogElement>) => {
    if (e.target === dialogRef.current) {
      onClose();
    }
  };

  return (
    <dialog ref={dialogRef} className="modal-dialog" onClick={handleBackdropClick}>
      <div className="modal">
        <div className="modal__header">
          <h2 className="modal__title">Edit Workspace</h2>
          <button
            type="button"
            className="modal__close"
            onClick={onClose}
            aria-label="Close"
          >
            ×
          </button>
        </div>

        <form className="modal__body" onSubmit={handleSubmit}>
          {error && (
            <div className="modal__error" role="alert">
              {error}
            </div>
          )}

          <div className="modal__field">
            <label htmlFor="workspace-name" className="modal__label">
              Workspace Name <span className="modal__required">*</span>
            </label>
            <input
              id="workspace-name"
              type="text"
              className="modal__input"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Workspace name"
              required
              autoFocus
              maxLength={200}
            />
          </div>

          <div className="modal__actions">
            <button
              type="submit"
              className="detail__btn detail__btn--primary"
              disabled={isSubmitting || !name.trim()}
            >
              {isSubmitting ? 'Saving...' : 'Save'}
            </button>
            <button
              type="button"
              className="detail__btn detail__btn--secondary"
              onClick={onClose}
              disabled={isSubmitting}
            >
              Cancel
            </button>
          </div>
        </form>
      </div>
    </dialog>
  );
}

export default WorkspaceEditModal;
