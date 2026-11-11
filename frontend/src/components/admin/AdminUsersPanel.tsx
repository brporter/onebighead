import { useId, useState } from 'react';
import { useAdminUsers, type AdminUsersPort } from '../../data/admin/useAdminUsers';
import { AdminResource } from './AdminResource';
import { useEditorStatus, type EditorStatusListener } from '../../data/shared/useEditorStatus';

export function AdminUsersPanel({ gateway, currentUserId, onStatusChange }: { gateway: AdminUsersPort; currentUserId: number; onStatusChange?: EditorStatusListener }) {
  const [search, setSearch] = useState('');
  const [query, setQuery] = useState('');
  const resource = useAdminUsers(query, gateway);
  useEditorStatus(false, resource.pending, onStatusChange);
  const users = resource.data ?? [];
  const id = useId();
  return <section className="admin-panel" aria-label="User administration">
    <h2 className="admin-panel__title">Users</h2>
    <form className="admin-panel__search" role="search" onSubmit={event => {
      event.preventDefault();
      if (query === search.trim()) resource.retry();
      else setQuery(search.trim());
    }}>
      <label htmlFor={id}>Email contains</label>
      <input id={id} type="search" value={search} onChange={event => setSearch(event.target.value)} placeholder="Name or email address" />
      <button type="submit" className="admin-panel__button">Search</button>
      {(search || query) && <button type="button" className="admin-panel__button" onClick={() => { setSearch(''); setQuery(''); }}>Clear</button>}
    </form>
    <AdminResource {...resource} empty={users.length === 0} subject="users">
      <div className="admin-panel__table-scroll" role="region" aria-label="User accounts" tabIndex={0}>
        <table className="admin-panel__table">
          <caption>{users.length} users</caption>
          <thead><tr><th scope="col">Email</th><th scope="col">Active workspace</th><th scope="col">Provider</th><th scope="col">System admin</th><th scope="col">Created</th><th scope="col">Actions</th></tr></thead>
          <tbody>{users.map(user => <tr key={user.userId}>
            <th scope="row">{user.email}{user.userId === currentUserId && ' (you)'}</th><td>{user.workspaceName || '—'}</td><td>{user.identityProvider}</td>
            <td><label className="admin-panel__permission"><input type="checkbox" aria-label={`System administrator for ${user.email}`} checked={user.isSystemAdministrator}
              disabled={resource.pending} onChange={() => {
                if (user.userId === currentUserId && user.isSystemAdministrator &&
                  !window.confirm('Remove your system administrator access? You will leave administration after this change.')) return;
                void resource.setAdministrator(user.userId, !user.isSystemAdministrator);
              }} /></label></td>
            <td>{new Date(user.createdAt).toLocaleDateString()}</td>
            <td><button type="button" className="admin-panel__button admin-panel__button--danger" disabled={resource.pending}
              aria-label={`Delete user ${user.email}`} onClick={() => {
                const message = user.userId === currentUserId
                  ? 'Permanently delete your account and memberships? You will be signed out.'
                  : `Delete user "${user.email}"?`;
                if (window.confirm(message)) void resource.remove(user.userId);
              }}>Delete</button></td>
          </tr>)}</tbody>
        </table>
      </div>
    </AdminResource>
  </section>;
}
