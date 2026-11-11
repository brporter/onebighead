import { useEffect, useRef, useState } from 'react';
import type { ItemTemplate, CreateItemTemplateRequest, UpdateItemTemplateRequest } from '../../utils/types';
import type { bulkUpdatesApi } from '../../api/bulkUpdates';
import type { ScopeOption } from '../bulkUpdates/types';
import { getErrorMessage } from '../../utils/errorUtils';
import { useAsyncAction } from '../../utils/useAsyncAction';
import { createTemplateDraft, sameTemplateDraft, templatePropertyChanges, templateRequest, type TemplatePropertyChanges } from './templateDefinition';

export interface TemplateDefinitionPort {
  createItemTemplate: (request: CreateItemTemplateRequest) => Promise<ItemTemplate>;
  updateItemTemplate: (id: number, request: UpdateItemTemplateRequest) => Promise<ItemTemplate>;
}
interface SavedDefinition { template: ItemTemplate; changes: TemplatePropertyChanges }

/** One mounted editing session owns a draft, one save, and any post-save preview. */
export function useTemplateDefinition(template: ItemTemplate | null, commands: TemplateDefinitionPort,
  previews: Pick<typeof bulkUpdatesApi, 'preview'>, onSaved: () => void, onDone: () => void) {
  const [original] = useState(() => createTemplateDraft(template));
  const [draft, setDraft] = useState(original);
  const action = useAsyncAction();
  const [saved, setSaved] = useState<SavedDefinition | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [scopeOptions, setScopeOptions] = useState<ScopeOption[] | null>(null);
  const preview = useRef<AbortController | null>(null);
  const mounted = useRef(true);
  const persisted = useRef(false);
  const [isSaved, setIsSaved] = useState(false);
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; preview.current?.abort(); };
  }, []);

  async function checkRelatedItems(definition: SavedDefinition) {
    preview.current?.abort();
    const controller = new AbortController();
    preview.current = controller;
    setPreviewLoading(true);
    setPreviewError(null);
    try {
      const result = await previews.preview({ scope: 'template', templateKey: definition.template.templateKey }, { signal: controller.signal });
      if (controller.signal.aborted) return;
      if (result.affectedItemCount > 0) setScopeOptions([{
        scope: 'template', templateKey: definition.template.templateKey,
        label: 'created from this template', count: result.affectedItemCount,
      }]);
      else onDone();
    } catch (cause) {
      if (!controller.signal.aborted) setPreviewError(getErrorMessage(cause, 'Unable to check related items'));
    } finally {
      if (!controller.signal.aborted) setPreviewLoading(false);
    }
  }

  function save() {
    if (persisted.current) return;
    return action.run(async () => {
      const request = templateRequest(draft);
      const updated = template === null
        ? await commands.createItemTemplate(request)
        : await commands.updateItemTemplate(template.itemTemplateId, request);
      if (!mounted.current) return;
      persisted.current = true;
      setIsSaved(true);
      onSaved();
      const changes = template === null ? null : templatePropertyChanges(original, draft);
      if (changes === null) { onDone(); return; }
      const definition = { template: updated, changes };
      setSaved(definition);
      await checkRelatedItems(definition);
    }, 'Unable to save template');
  }

  return { draft, setDraft, dirty: !isSaved && !sameTemplateDraft(original, draft),
    save, saving: action.pending, error: action.error, saved, scopeOptions, previewLoading, previewError,
    retryPreview: () => { if (saved) void checkRelatedItems(saved); } };
}
