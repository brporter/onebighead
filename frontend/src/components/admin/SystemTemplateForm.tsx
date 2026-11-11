import type { ItemTemplate } from '../../utils/types';
import { useSystemTemplateDefinition } from '../../data/admin/useSystemTemplateDefinition';
import type { AdminTemplatesPort } from '../../data/admin/useAdminTemplates';
import { TemplateDraftForm } from '../template/TemplateDraftForm';
import { useEditorStatus, type EditorStatusListener } from '../../data/shared/useEditorStatus';

interface SystemTemplateFormProps {
  template: ItemTemplate | null;
  commands: Pick<AdminTemplatesPort, 'createSystemTemplate' | 'updateSystemTemplate'>;
  onSaved: () => void;
  onCancel: () => void;
  onStatusChange?: EditorStatusListener;
}

export function SystemTemplateForm({ template, commands, onSaved, onCancel, onStatusChange }: SystemTemplateFormProps) {
  const editor = useSystemTemplateDefinition(template, commands, onSaved);
  useEditorStatus(editor.dirty, editor.saving, onStatusChange);
  return <TemplateDraftForm {...editor} title={template === null ? 'Create System Template' : `Edit: ${template.name}`}
    notice="System templates are available across all workspaces." saveLabel={template === null ? 'Create Template' : 'Save Changes'}
    onSave={editor.save} onCancel={() => {
      if (!editor.dirty || window.confirm('Discard unsaved template changes?')) onCancel();
    }} />;
}
