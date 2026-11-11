import { useEffect, useId, useRef } from 'react';
import type { WorkspaceMembership } from '../../utils/types';
import { workspacesApi } from '../../api';
import { useWorkspaceDraft } from '../../data/workspaces/useWorkspaceDraft';
import { ModalDialog } from '../common/ModalDialog';
import { useEditorStatus, type EditorStatusListener } from '../../data/shared/useEditorStatus';
import '../../styles/components/WorkspaceEditModal.css';

interface WorkspaceEditModalProps {
  workspace: WorkspaceMembership | null;
  isOpen: boolean;
  onClose: () => void;
  refresh: () => Promise<void>;
  onSaved?: () => void;
  onStatusChange?: EditorStatusListener;
}

function WorkspaceEditor({ workspace, onClose, refresh, onSaved, onStatusChange }: Omit<WorkspaceEditModalProps, 'workspace' | 'isOpen'> & { workspace: WorkspaceMembership }) {
  const id = useId();
  const editor = useWorkspaceDraft(workspace, workspacesApi.update, refresh, () => {
    onSaved?.();
    onClose();
  });
  const locked = editor.pending || editor.reviewRequired;
  const errorRef = useRef<HTMLDivElement>(null);
  useEffect(() => { if (editor.error) errorRef.current!.focus(); }, [editor.error]);
  useEditorStatus(editor.dirty, locked, onStatusChange);
  const dismiss = () => {
    if (locked) return;
    if (editor.dirty && !window.confirm('Discard your unsaved workspace changes?')) return;
    onClose();
  };

  return <ModalDialog label="Edit Workspace" onClose={dismiss}>
    <div className="modal workspace-edit-modal">
      <div className="modal__header">
        <h2 className="modal__title">Edit Workspace</h2>
        <button type="button" className="modal__close" onClick={dismiss} disabled={locked} aria-label="Close">&times;</button>
      </div>
      <form className="modal__body" aria-label="Edit workspace details" onSubmit={event => { event.preventDefault(); void editor.save(); }}>
        {editor.error && <div ref={errorRef} tabIndex={-1} className="modal__error" role="alert">{editor.error}</div>}
        {editor.reviewRequired && <div role="status">
          <p>Refresh your workspace details before continuing.</p>
          <button type="button" className="modal__button modal__button--secondary" disabled={editor.pending} onClick={() => { void editor.save(); }}>Retry workspace refresh</button>
        </div>}
        <fieldset className="workspace-edit-modal__fields" disabled={locked}>
          <div className="modal__field">
            <label htmlFor={`${id}-name`} className="modal__label">Workspace Name<span className="modal__required" aria-hidden="true"> *</span></label>
            <input id={`${id}-name`} type="text" className="modal__input" value={editor.draft.name}
              onChange={event => editor.setDraft({ ...editor.draft, name: event.target.value })}
              placeholder="Workspace name" required autoFocus maxLength={200} />
          </div>
          <h3 className="workspace-edit-modal__section-title">Public Gallery</h3>
          <div className="modal__field">
            <label htmlFor={`${id}-slug`} className="modal__label">Gallery URL Slug</label>
            <input id={`${id}-slug`} type="text" className="modal__input" value={editor.draft.slug}
              onChange={event => editor.setDraft({ ...editor.draft, slug: event.target.value.toLowerCase().replace(/[^a-z0-9-]/g, '') })}
              aria-describedby={`${id}-hint`} placeholder="my-workspace" maxLength={50} />
            <p id={`${id}-hint`} className="workspace-edit-modal__hint">Reserve your gallery URL. Your gallery becomes active when you publish your first item.</p>
          </div>
          {editor.draft.slug.trim() && <div className="workspace-edit-modal__preview">
            <span className="workspace-edit-modal__preview-label">Gallery URL:</span>
            <code className="workspace-edit-modal__preview-url">/public/{editor.draft.slug.trim()}</code>
          </div>}
          <div className="modal__actions">
            <button type="submit" className="modal__button modal__button--primary" disabled={editor.pending || !editor.draft.name.trim()}>{editor.pending ? 'Saving...' : 'Save'}</button>
            <button type="button" className="modal__button modal__button--secondary" onClick={dismiss}>Cancel</button>
          </div>
        </fieldset>
      </form>
    </div>
  </ModalDialog>;
}

/** Closing or changing workspace ends the old editor, including its pending callbacks. */
export default function WorkspaceEditModal({ workspace, isOpen, ...props }: WorkspaceEditModalProps) {
  return isOpen && workspace ? <WorkspaceEditor key={workspace.workspaceId} workspace={workspace} {...props} /> : null;
}
