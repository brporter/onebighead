import React, { useState, useEffect, useRef } from 'react';
import type { WorkspaceMembership } from '../../utils/types';
import { workspacesApi } from '../../api';
import '../../styles/components/WorkspaceEditModal.css';

interface WorkspaceEditModalProps {
  workspace: WorkspaceMembership | null;
  isOpen: boolean;
  onClose: () => void;
  onSaved?: () => void;
}

function toSlug(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 50);
}

function isValidSlug(slug: string): boolean {
  return /^[a-z0-9]([a-z0-9]|-(?!-))*[a-z0-9]$/.test(slug) && slug.length >= 3 && slug.length <= 50;
}

function WorkspaceEditModal({ workspace, isOpen, onClose, onSaved }: WorkspaceEditModalProps) {
  const [name, setName] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const dialogRef = useRef<HTMLDialogElement>(null);

  // Public access state
  const [publicAccessSlug, setPublicAccessSlug] = useState('');
  const [publicAccessEnabled, setPublicAccessEnabled] = useState(false);
  const [publicAccessLoading, setPublicAccessLoading] = useState(false);

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

  // Reset form and load public access data when modal opens
  useEffect(() => {
    if (isOpen && workspace) {
      setName(workspace.workspaceName);
      setError(null);

      // Load public access settings
      setPublicAccessLoading(true);
      workspacesApi.getPublicAccess(workspace.workspaceId)
        .then((data) => {
          setPublicAccessSlug(data.slug || '');
          setPublicAccessEnabled(data.isPublicAccessEnabled);
        })
        .catch(() => {
          // Auto-suggest slug from workspace name if we couldn't load
          const suggestedSlug = toSlug(workspace.workspaceName);
          setPublicAccessSlug(suggestedSlug);
          setPublicAccessEnabled(false);
        })
        .finally(() => setPublicAccessLoading(false));
    }
  }, [isOpen, workspace]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const trimmedName = name.trim();
    if (!trimmedName) {
      setError('Workspace name is required');
      return;
    }

    const slug = publicAccessSlug.trim();

    if (publicAccessEnabled && !slug) {
      setError('A URL slug is required to enable public access.');
      return;
    }

    if (slug && !isValidSlug(slug)) {
      setError('Slug must be 3-50 characters, lowercase letters, numbers, and hyphens only. Must start and end with a letter or number.');
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

          <div className="modal__divider" />

          <h3 className="modal__section-title">Public Access</h3>

          {publicAccessLoading ? (
            <p className="workspace-edit-modal__loading">Loading public access settings...</p>
          ) : (
            <>
              <div className="modal__field">
                <label htmlFor="public-slug" className="modal__label">
                  Public URL Slug
                </label>
                <input
                  id="public-slug"
                  type="text"
                  className="modal__input"
                  value={publicAccessSlug}
                  onChange={(e) => {
                    const val = e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, '');
                    setPublicAccessSlug(val);
                    setError(null);
                  }}
                  placeholder="my-workspace"
                  maxLength={50}
                />
                <p className="modal__hint">
                  Lowercase letters, numbers, and hyphens only. 3-50 characters.
                </p>
              </div>

              <div className="modal__field">
                <label className="workspace-edit-modal__toggle-label">
                  <input
                    type="checkbox"
                    checked={publicAccessEnabled}
                    onChange={(e) => {
                      setPublicAccessEnabled(e.target.checked);
                      setError(null);
                    }}
                    disabled={!publicAccessSlug.trim()}
                  />
                  <span>Enable Public Access</span>
                </label>
                {!publicAccessSlug.trim() && (
                  <p className="modal__hint">Set a slug above to enable public access.</p>
                )}
              </div>

              {publicAccessEnabled && publicAccessSlug.trim() && (
                <div className="workspace-edit-modal__preview">
                  <span className="workspace-edit-modal__preview-label">Public URL:</span>
                  <code className="workspace-edit-modal__preview-url">/public/{publicAccessSlug.trim()}</code>
                </div>
              )}
            </>
          )}

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
