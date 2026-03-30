import React, { useState, useEffect } from 'react';
import type { WorkspaceMembership } from '../../utils/types';
import { workspacesApi } from '../../api';
import { toSlug, isValidSlug } from '../../utils/slugUtils';
import { useDialog } from '../../utils/useDialog';
import '../../styles/components/WorkspaceEditModal.css';

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
  const [dialogRef, handleBackdropClick] = useDialog(isOpen, onClose);

  // Slug state
  const [slug, setSlug] = useState('');

  // Reset form when modal opens
  useEffect(() => {
    if (isOpen && workspace) {
      setName(workspace.workspaceName);
      setSlug(workspace.slug || toSlug(workspace.workspaceName));
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

    const trimmedSlug = slug.trim();

    if (trimmedSlug && !isValidSlug(trimmedSlug)) {
      setError('Slug must be 3-50 characters, lowercase letters, numbers, and hyphens only. Must start and end with a letter or number.');
      return;
    }

    if (!workspace) return;

    setIsSubmitting(true);
    setError(null);

    try {
      await workspacesApi.update(workspace.workspaceId, {
        name: trimmedName,
        slug: trimmedSlug || null,
      });
      onSaved?.();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setIsSubmitting(false);
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
            &times;
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

          <h3 className="modal__section-title">Public Gallery</h3>

          <div className="modal__field">
            <label htmlFor="public-slug" className="modal__label">
              Gallery URL Slug
            </label>
            <input
              id="public-slug"
              type="text"
              className="modal__input"
              value={slug}
              onChange={(e) => {
                const val = e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, '');
                setSlug(val);
                setError(null);
              }}
              placeholder="my-workspace"
              maxLength={50}
            />
            <p className="modal__hint">
              Reserve your gallery URL. Your gallery becomes active when you publish your first item.
            </p>
          </div>

          {slug.trim() && (
            <div className="workspace-edit-modal__preview">
              <span className="workspace-edit-modal__preview-label">Gallery URL:</span>
              <code className="workspace-edit-modal__preview-url">/public/{slug.trim()}</code>
            </div>
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
