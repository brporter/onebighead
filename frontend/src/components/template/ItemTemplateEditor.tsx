import { useId, useState } from 'react';
import { useTemplatesData } from '../../contexts/useData';
import { bulkUpdatesApi } from '../../api/bulkUpdates';
import type { ItemTemplate } from '../../utils/types';
import { useTemplateLibrary } from '../../data/templates/useTemplateLibrary';
import { ContentState } from '../common/ContentState';
import { TemplateCard } from './TemplateCard';
import { TemplateDefinitionForm } from './TemplateDefinitionForm';
import { useEditorStatus, type EditorStatus, type EditorStatusListener } from '../../data/shared/useEditorStatus';
import '../../styles/ItemTemplateEditor.css';

interface ItemTemplateEditorProps {
  onClose: () => void;
  onStatusChange?: EditorStatusListener;
  isFullPage?: boolean;
}
type Filter = 'all' | 'system' | 'workspace';

export default function ItemTemplateEditor({ onClose, onStatusChange, isFullPage = false }: ItemTemplateEditorProps) {
  const commands = useTemplatesData();
  const library = useTemplateLibrary(commands);
  const [session, setSession] = useState<{ template: ItemTemplate | null } | null>(null);
  const [editorStatus, setEditorStatus] = useState<EditorStatus>({ dirty: false, pending: false });
  useEditorStatus(session !== null && editorStatus.dirty, library.deleting || (session !== null && editorStatus.pending), onStatusChange);
  const [filter, setFilter] = useState<Filter>('all');
  const id = useId();
  const groups = [
    { filter: 'workspace', title: 'My Templates', templates: library.data?.filter(template => !template.isSystem) ?? [] },
    { filter: 'system', title: 'System Templates', templates: library.data?.filter(template => template.isSystem) ?? [] },
  ].filter(group => filter === 'all' || group.filter === filter);

  function remove(template: ItemTemplate) {
    if (window.confirm(`Delete "${template.name}"? Existing items will be kept.`)) void library.remove(template.itemTemplateId);
  }

  return <div className={`template-editor${isFullPage ? ' template-editor--fullpage' : ''}`}>
    {session ? <TemplateDefinitionForm template={session.template} commands={commands} previews={bulkUpdatesApi}
      onSaved={library.refresh} onDone={() => setSession(null)} onStatusChange={setEditorStatus} /> : <>
      <div className="template-editor__header">
        <div className="template-editor__headerContent">
          <h2 className="template-editor__title">Item Templates</h2>
          <p className="template-editor__description">Define reusable properties for your items. Start with a system template or create your own.</p>
        </div>
        <button type="button" className="template-editor__addBtn" disabled={library.deleting} onClick={() => setSession({ template: null })}>+ New Template</button>
      </div>
      <div className="template-editor__filters">
        <label className="template-editor__filterLabel" htmlFor={`${id}-filter`}>Show</label>
        <select id={`${id}-filter`} className="template-editor__filterSelect" value={filter} onChange={event => setFilter(event.target.value as Filter)}>
          <option value="all">All Templates</option><option value="workspace">My Templates</option><option value="system">System Templates</option>
        </select>
      </div>
      {library.deleteError && <ContentState kind="error" title="Unable to delete template">{library.deleteError}</ContentState>}
      {library.deleting && <ContentState kind="loading" title="Deleting template…" />}
      {library.loading ? <ContentState kind="loading" title="Loading templates…" /> : library.error ?
        <ContentState kind="error" title="Unable to load templates" action={<button type="button" onClick={library.refresh}>Retry</button>}>{library.error}</ContentState> :
        <div className="template-editor__content">
          {groups.map(group => group.templates.length > 0 && <section key={group.filter} className="template-editor__section" aria-label={group.title}>
            <h3 className="template-editor__sectionTitle">{group.title}</h3>
            <div className="template-editor__grid">{group.templates.map(template => <TemplateCard key={template.itemTemplateId} template={template}
              disabled={library.deleting} onEdit={template => setSession({ template })} onDelete={remove} />)}</div>
          </section>)}
          {groups.every(group => group.templates.length === 0) && <ContentState kind="empty" title="No templates to show">
            Create a template or choose a different filter.
          </ContentState>}
        </div>}
      <div><button type="button" className="detail__btn detail__btn--secondary" disabled={library.deleting} onClick={onClose}>Back</button></div>
    </>}
  </div>;
}
