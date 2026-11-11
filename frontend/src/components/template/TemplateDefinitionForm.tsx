import { useState } from 'react';
import type { ItemTemplate } from '../../utils/types';
import type { bulkUpdatesApi } from '../../api/bulkUpdates';
import { BulkUpdateModal } from '../common/BulkUpdateModal';
import { ContentState } from '../common/ContentState';
import { TemplateDraftForm } from './TemplateDraftForm';
import { useTemplateDefinition, type TemplateDefinitionPort } from '../../data/templates/useTemplateDefinition';
import { useEditorStatus, type EditorStatus, type EditorStatusListener } from '../../data/shared/useEditorStatus';
import '../../styles/components/TemplateDefinitionForm.css';

interface TemplateDefinitionFormProps {
  template: ItemTemplate | null;
  commands: TemplateDefinitionPort;
  previews: Pick<typeof bulkUpdatesApi, 'preview'>;
  onSaved: () => void;
  onDone: () => void;
  onStatusChange?: EditorStatusListener;
}

export function TemplateDefinitionForm({ template, commands, previews, onSaved, onDone, onStatusChange }: TemplateDefinitionFormProps) {
  const editor = useTemplateDefinition(template, commands, previews, onSaved, onDone);
  const [bulkStatus, setBulkStatus] = useState<EditorStatus>({ dirty: false, pending: false });
  // A committed definition may leave its cancellable preview. Only writes and
  // active bulk jobs need to hold navigation after the draft is saved.
  const pending = (editor.saved === null && editor.saving) || bulkStatus.pending;
  useEditorStatus(editor.dirty, pending, onStatusChange);

  const cancel = () => {
    if (!editor.dirty || window.confirm('Discard unsaved template changes?')) onDone();
  };
  if (editor.saved) return <div className="template-form">
    <ContentState kind="empty" title="Template saved">
      <p>Your template is saved. You can also apply its property changes to existing items.</p>
    </ContentState>
    {editor.previewLoading && <ContentState kind="loading" title="Checking related items…" />}
    {editor.previewError && <ContentState kind="error" title="Unable to check related items"
      action={<button type="button" onClick={editor.retryPreview}>Retry check</button>}>{editor.previewError}</ContentState>}
    <div className="template-form__actions"><button type="button" className="template-form__btn template-form__btn--secondary" disabled={pending} onClick={onDone}>Back to templates</button></div>
    {editor.scopeOptions && <BulkUpdateModal isOpen onClose={onDone} onComplete={onDone}
      scopeOptions={editor.scopeOptions} onStatusChange={setBulkStatus} {...editor.saved.changes} />}
  </div>;

  return <TemplateDraftForm draft={editor.draft} setDraft={editor.setDraft}
    title={template === null ? 'Create New Template' : template.isSystem ? `Customize: ${template.name}` : `Edit: ${template.name}`}
    notice={template?.isSystem ? 'Saving creates a custom copy for this workspace.' : undefined}
    saving={editor.saving} error={editor.error} onSave={editor.save} onCancel={cancel}
    saveLabel={template === null ? 'Create Template' : template.isSystem ? 'Save Custom Copy' : 'Save Changes'} />;
}
