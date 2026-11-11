import { useState } from 'react';
import type { ItemTemplate } from '../../utils/types';
import { useAsyncAction } from '../../utils/useAsyncAction';
import { createTemplateDraft, sameTemplateDraft, templateRequest } from '../templates/templateDefinition';
import type { AdminTemplatesPort } from './useAdminTemplates';

export function useSystemTemplateDefinition(template: ItemTemplate | null,
  commands: Pick<AdminTemplatesPort, 'createSystemTemplate' | 'updateSystemTemplate'>, onSaved: () => void) {
  const [original] = useState(() => createTemplateDraft(template));
  const [draft, setDraft] = useState(original);
  const action = useAsyncAction();
  const save = () => action.run(() => {
    const request = templateRequest(draft);
    return template === null ? commands.createSystemTemplate(request) : commands.updateSystemTemplate(template.itemTemplateId, request);
  }, 'Unable to save system template', onSaved);
  return { draft, setDraft, save, dirty: !sameTemplateDraft(original, draft), saving: action.pending, error: action.error };
}
