import { useEffect } from 'react';
import { useTemplatesData } from '../../contexts/useData';
import type { Collection, ItemTemplate } from '../../utils/types';
import { useTemplateCatalog } from '../../data/templates/useTemplateCatalog';
import { useTemplateAssignments, type TemplateAssignmentsPort } from '../../data/templates/useTemplateAssignments';
import { ContentState } from '../common/ContentState';
import { TemplateChecklist } from '../template/TemplateChecklist';
import { useEditorStatus, type EditorStatusListener } from '../../data/shared/useEditorStatus';
import '../../styles/components/CollectionTemplateEditor.css';

interface CollectionTemplateEditorProps {
  collection: Collection;
  onClose: () => void;
  onDirtyChange?: (isDirty: boolean) => void;
  onStatusChange?: EditorStatusListener;
}

function CollectionTemplateEditor(props: CollectionTemplateEditorProps) {
  return <CollectionTemplateSession key={props.collection.collectionId} {...props} />;
}

function CollectionTemplateSession({ collection, onClose, onDirtyChange, onStatusChange }: CollectionTemplateEditorProps) {
  const data = useTemplatesData();
  const catalog = useTemplateCatalog(collection.collectionId, data);
  return <section className="template-assignment">
    <h3 className="template-assignment__title">Templates for "{collection.name}"</h3>
    {catalog.loading ? <ContentState kind="loading" title="Loading templates..." /> :
      catalog.error ? <ContentState kind="error" title="Unable to load templates"
        action={<button type="button" onClick={catalog.retry}>Try again</button>}>{catalog.error}</ContentState> :
        <TemplateAssignments collectionId={collection.collectionId} templates={catalog.data!.available}
          initialIds={catalog.data!.collection.map(template => template.itemTemplateId)} commands={data}
          onClose={onClose} onDirtyChange={onDirtyChange} onStatusChange={onStatusChange} />}
    {(catalog.loading || catalog.error) && <button type="button" className="detail__btn detail__btn--secondary" onClick={onClose}>Back</button>}
  </section>;
}

interface TemplateAssignmentsProps {
  collectionId: number;
  templates: ItemTemplate[];
  initialIds: number[];
  commands: TemplateAssignmentsPort;
  onClose: () => void;
  onDirtyChange?: (dirty: boolean) => void;
  onStatusChange?: EditorStatusListener;
}

function TemplateAssignments({ collectionId, templates, initialIds, commands, onClose, onDirtyChange, onStatusChange }: TemplateAssignmentsProps) {
  const assignment = useTemplateAssignments(collectionId, initialIds, commands);
  useEffect(() => { onDirtyChange?.(assignment.dirty); }, [assignment.dirty, onDirtyChange]);
  useEffect(() => () => { onDirtyChange?.(false); }, [onDirtyChange]);
  useEditorStatus(assignment.dirty, assignment.saving, onStatusChange);
  const cancel = () => {
    if (assignment.dirty && !window.confirm('You have unsaved changes. Discard them?')) return;
    onClose();
  };
  return <>
    <p className="template-assignment__description">Select which templates should be available when creating new items in this collection.
      Templates not selected here can still be used from the full template library.</p>
    {assignment.error && <ContentState kind="error" title="Some changes could not be saved">{assignment.error}</ContentState>}
    {templates.length === 0 ? <ContentState kind="empty" title="No templates available."
      >Create templates in the "Item Templates" section first.</ContentState> :
      <TemplateChecklist label="Collection templates" templates={templates} selectedIds={assignment.selectedIds}
        onChange={assignment.select} disabled={assignment.saving} />}
    <div className="template-assignment__actions" aria-busy={assignment.saving}>
      <button type="button" className="detail__btn detail__btn--primary" onClick={() => void assignment.save()}
        disabled={assignment.saving || !assignment.dirty}>{assignment.saving ? 'Saving...' : 'Save Changes'}</button>
      <button type="button" className="detail__btn detail__btn--secondary" onClick={cancel}
        disabled={assignment.saving}>{assignment.dirty ? 'Cancel' : 'Back'}</button>
    </div>
  </>;
}

export default CollectionTemplateEditor;
