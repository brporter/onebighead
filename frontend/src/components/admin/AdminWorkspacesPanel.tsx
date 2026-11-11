import { useAdminWorkspaces, type AdminWorkspacesPort } from '../../data/admin/useAdminWorkspaces';
import { AdminResource } from './AdminResource';
import { useEditorStatus, type EditorStatusListener } from '../../data/shared/useEditorStatus';

export function AdminWorkspacesPanel({ gateway, onStatusChange }: { gateway: AdminWorkspacesPort; onStatusChange?: EditorStatusListener }) {
  const resource = useAdminWorkspaces(gateway);
  useEditorStatus(false, resource.pending, onStatusChange);
  const workspaces = resource.data ?? [];
  return <section className="admin-panel" aria-label="Workspace administration">
    <h2 className="admin-panel__title">Workspaces</h2>
    <p className="admin-panel__description">Review workspace usage and manage workspace data.</p>
    <AdminResource {...resource} empty={workspaces.length === 0} subject="workspaces">
      <div className="admin-panel__table-scroll" role="region" aria-label="Workspace usage" tabIndex={0}>
        <table className="admin-panel__table">
          <caption>{workspaces.length} workspaces</caption>
          <thead><tr><th scope="col">Name</th><th scope="col">Users</th><th scope="col">Collections</th><th scope="col">Items</th><th scope="col">Images</th><th scope="col">Created</th><th scope="col">Actions</th></tr></thead>
          <tbody>{workspaces.map(workspace => <tr key={workspace.workspaceId}>
            <th scope="row">{workspace.name}</th><td>{workspace.userCount}</td><td>{workspace.collectionCount}</td><td>{workspace.itemCount}</td><td>{workspace.imageCount}</td><td>{new Date(workspace.createdAt).toLocaleDateString()}</td>
            <td><button type="button" className="admin-panel__button admin-panel__button--danger" disabled={resource.pending}
              aria-label={`Delete workspace ${workspace.name}`} onClick={() => {
                if (window.confirm(`Permanently delete workspace "${workspace.name}" and its collections, items and memberships?`)) void resource.remove(workspace.workspaceId);
              }}>Delete</button></td>
          </tr>)}</tbody>
        </table>
      </div>
    </AdminResource>
  </section>;
}
