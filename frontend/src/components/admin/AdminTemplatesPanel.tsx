import { useState } from 'react';
import type { ItemTemplate } from '../../utils/types';
import { useAdminTemplates, type AdminTemplatesPort } from '../../data/admin/useAdminTemplates';
import { AdminResource } from './AdminResource';
import { SystemTemplateForm } from './SystemTemplateForm';
import { useEditorStatus, type EditorStatus, type EditorStatusListener } from '../../data/shared/useEditorStatus';

export function AdminTemplatesPanel({ gateway, onStatusChange }: { gateway: AdminTemplatesPort; onStatusChange?: EditorStatusListener }) {
  const resource = useAdminTemplates(gateway);
  const [editing, setEditing] = useState<{ template: ItemTemplate | null } | null>(null);
  const [editorStatus, setEditorStatus] = useState<EditorStatus>({ dirty: false, pending: false });
  useEditorStatus(editing !== null && editorStatus.dirty, resource.pending || (editing !== null && editorStatus.pending), onStatusChange);
  const templates = resource.data ?? [];
  return <section className="admin-panel" aria-label="System template administration">
    {editing ? <SystemTemplateForm template={editing.template} commands={gateway} onStatusChange={setEditorStatus}
      onCancel={() => setEditing(null)} onSaved={() => { setEditing(null); resource.retry(); }} /> : <>
      <div className="admin-panel__heading">
        <h2 className="admin-panel__title">System Templates</h2>
        <button type="button" className="admin-panel__button admin-panel__button--primary" disabled={resource.pending}
          onClick={() => setEditing({ template: null })}>+ New Template</button>
      </div>
      <p className="admin-panel__description">Manage the shared starting points available to every workspace.</p>
      <AdminResource {...resource} empty={templates.length === 0} subject="system templates">
        <div className="admin-panel__table-scroll" role="region" aria-label="System templates" tabIndex={0}>
          <table className="admin-panel__table">
            <caption>{templates.length} system templates</caption>
            <thead><tr><th scope="col">Name</th><th scope="col">Description</th><th scope="col">Properties</th><th scope="col">Created</th><th scope="col">Actions</th></tr></thead>
            <tbody>{templates.map(template => <tr key={template.itemTemplateId}>
              <th scope="row">{template.name}</th><td>{template.description || '—'}</td><td>{template.properties.length}</td><td>{new Date(template.createdAt).toLocaleDateString()}</td>
              <td><div className="admin-panel__actions">
                <button type="button" className="admin-panel__button" disabled={resource.pending} aria-label={`Edit template ${template.name}`} onClick={() => setEditing({ template })}>Edit</button>
                <button type="button" className="admin-panel__button admin-panel__button--danger" disabled={resource.pending} aria-label={`Delete template ${template.name}`} onClick={() => {
                  if (window.confirm(`Delete system template "${template.name}"? Existing items will be kept.`)) void resource.remove(template.itemTemplateId);
                }}>Delete</button>
              </div></td>
            </tr>)}</tbody>
          </table>
        </div>
      </AdminResource>
    </>}
  </section>;
}
