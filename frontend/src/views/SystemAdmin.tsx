import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useUser } from '../contexts/UserContext';
import { adminApi } from '../api';
import { AdminSupportSection } from '../components/support/AdminSupportSection';
import type { WorkspaceSummary, UserSummary, ItemTemplate, CreateItemTemplateRequest } from '../utils/types';
import '../styles/SystemAdmin.css';

type AdminTab = 'workspaces' | 'users' | 'templates' | 'support';

function SystemAdmin() {
  const navigate = useNavigate();
  const { user, loading: userLoading, logout } = useUser();
  const [activeTab, setActiveTab] = useState<AdminTab>('workspaces');
  const [workspaces, setWorkspaces] = useState<WorkspaceSummary[]>([]);
  const [users, setUsers] = useState<UserSummary[]>([]);
  const [templates, setTemplates] = useState<ItemTemplate[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [userSearch, setUserSearch] = useState('');
  const [editingTemplate, setEditingTemplate] = useState<ItemTemplate | null>(null);
  const [isAddingTemplate, setIsAddingTemplate] = useState(false);
  const [templateForm, setTemplateForm] = useState({
    name: '',
    description: '',
    properties: [] as { category: string; name: string }[],
  });

  // Redirect if not admin
  useEffect(() => {
    if (user && !user.isSystemAdministrator) {
      navigate('/');
    }
  }, [user, navigate]);

  const loadWorkspaces = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await adminApi.getWorkspaces();
      setWorkspaces(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load workspaces');
    } finally {
      setLoading(false);
    }
  }, []);

  const loadUsers = useCallback(async (email?: string) => {
    setLoading(true);
    setError(null);
    try {
      const data = await adminApi.getUsers(email);
      setUsers(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load users');
    } finally {
      setLoading(false);
    }
  }, []);

  const loadTemplates = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await adminApi.getSystemTemplates();
      setTemplates(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load templates');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (userLoading || !user?.isSystemAdministrator) return;
    if (activeTab === 'workspaces') loadWorkspaces();
    else if (activeTab === 'users') loadUsers();
    else if (activeTab === 'templates') loadTemplates();
  }, [activeTab, user, userLoading, loadWorkspaces, loadUsers, loadTemplates]);

  const handleDeleteWorkspace = async (workspaceId: number, workspaceName: string) => {
    if (!confirm(`Are you sure you want to delete workspace "${workspaceName}"? This will permanently delete all users, collections, items, and data associated with this workspace.`)) {
      return;
    }
    try {
      await adminApi.deleteWorkspace(workspaceId);
      setWorkspaces(workspaces.filter(w => w.workspaceId !== workspaceId));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete workspace');
    }
  };

  const handleDeleteUser = async (userId: number, email: string) => {
    if (!confirm(`Are you sure you want to delete user "${email}"?`)) {
      return;
    }
    try {
      await adminApi.deleteUser(userId);
      setUsers(users.filter(u => u.userId !== userId));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete user');
    }
  };

  const handleToggleAdmin = async (userId: number, currentStatus: boolean) => {
    try {
      const updatedUser = await adminApi.setAdminStatus(userId, !currentStatus);
      setUsers(users.map(u => u.userId === userId ? updatedUser : u));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update admin status');
    }
  };

  const handleUserSearch = (e: React.FormEvent) => {
    e.preventDefault();
    loadUsers(userSearch || undefined);
  };

  const handleAddTemplateClick = () => {
    setTemplateForm({ name: '', description: '', properties: [] });
    setIsAddingTemplate(true);
    setEditingTemplate(null);
  };

  const handleEditTemplateClick = (template: ItemTemplate) => {
    setTemplateForm({
      name: template.name,
      description: template.description,
      properties: template.properties.map(p => ({ category: p.category, name: p.name })),
    });
    setEditingTemplate(template);
    setIsAddingTemplate(false);
  };

  const handleCancelTemplateEdit = () => {
    setIsAddingTemplate(false);
    setEditingTemplate(null);
  };

  const handleAddProperty = () => {
    setTemplateForm(prev => ({
      ...prev,
      properties: [...prev.properties, { category: '', name: '' }],
    }));
  };

  const handleRemoveProperty = (index: number) => {
    setTemplateForm(prev => ({
      ...prev,
      properties: prev.properties.filter((_, i) => i !== index),
    }));
  };

  const handlePropertyChange = (index: number, field: 'category' | 'name', value: string) => {
    setTemplateForm(prev => ({
      ...prev,
      properties: prev.properties.map((p, i) => i === index ? { ...p, [field]: value } : p),
    }));
  };

  const handleSaveTemplate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!templateForm.name.trim()) {
      setError('Template name is required');
      return;
    }

    try {
      const request: CreateItemTemplateRequest = {
        name: templateForm.name.trim(),
        description: templateForm.description.trim(),
        properties: templateForm.properties
          .filter(p => p.category.trim() && p.name.trim())
          .map(p => ({ category: p.category.trim(), name: p.name.trim() })),
      };

      if (editingTemplate) {
        await adminApi.updateSystemTemplate(editingTemplate.itemTemplateId, request);
      } else {
        await adminApi.createSystemTemplate(request);
      }

      await loadTemplates();
      setIsAddingTemplate(false);
      setEditingTemplate(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save template');
    }
  };

  const handleDeleteTemplate = async (templateId: number, templateName: string) => {
    if (!confirm(`Are you sure you want to delete the system template "${templateName}"?`)) {
      return;
    }
    try {
      await adminApi.deleteSystemTemplate(templateId);
      setTemplates(templates.filter(t => t.itemTemplateId !== templateId));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete template');
    }
  };

  const handleSignOut = async () => {
    await logout();
    window.location.href = '/';
  };

  if (userLoading) {
    return <div className="systemAdmin"><p style={{ padding: '2rem' }}>Loading...</p></div>;
  }

  if (!user?.isSystemAdministrator) {
    return null;
  }

  const isEditingTemplate = isAddingTemplate || editingTemplate !== null;

  return (
    <div className="systemAdmin">
      <header className="systemAdmin__header">
        <h1 className="systemAdmin__title">System Administration</h1>
        <div className="systemAdmin__headerActions">
          <button className="systemAdmin__backButton" onClick={() => navigate('/')}>
            ← Back to App
          </button>
          <button className="systemAdmin__signOutButton" onClick={handleSignOut}>
            Sign Out
          </button>
        </div>
      </header>

      <nav className="systemAdmin__tabs">
        <button
          className={`systemAdmin__tab ${activeTab === 'workspaces' ? 'systemAdmin__tab--active' : ''}`}
          onClick={() => setActiveTab('workspaces')}
        >
          Workspaces
        </button>
        <button
          className={`systemAdmin__tab ${activeTab === 'users' ? 'systemAdmin__tab--active' : ''}`}
          onClick={() => setActiveTab('users')}
        >
          Users
        </button>
        <button
          className={`systemAdmin__tab ${activeTab === 'templates' ? 'systemAdmin__tab--active' : ''}`}
          onClick={() => setActiveTab('templates')}
        >
          System Templates
        </button>
        <button
          className={`systemAdmin__tab ${activeTab === 'support' ? 'systemAdmin__tab--active' : ''}`}
          onClick={() => setActiveTab('support')}
        >
          Support
        </button>
      </nav>

      {error && <div className="systemAdmin__error">{error}</div>}

      <div className="systemAdmin__content">
        {loading && <p className="systemAdmin__loading">Loading...</p>}

        {!loading && activeTab === 'workspaces' && (
          <div className="systemAdmin__section">
            <h2 className="systemAdmin__sectionTitle">Workspaces ({workspaces.length})</h2>
            <table className="systemAdmin__table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Users</th>
                  <th>Collections</th>
                  <th>Items</th>
                  <th>Images</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {workspaces.map(workspace => (
                  <tr key={workspace.workspaceId}>
                    <td>{workspace.name}</td>
                    <td>{workspace.userCount}</td>
                    <td>{workspace.collectionCount}</td>
                    <td>{workspace.itemCount}</td>
                    <td>{workspace.imageCount}</td>
                    <td>{new Date(workspace.createdAt).toLocaleDateString()}</td>
                    <td>
                      <button
                        className="systemAdmin__actionButton systemAdmin__actionButton--danger"
                        onClick={() => handleDeleteWorkspace(workspace.workspaceId, workspace.name)}
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {!loading && activeTab === 'users' && (
          <div className="systemAdmin__section">
            <h2 className="systemAdmin__sectionTitle">Users ({users.length})</h2>
            <form className="systemAdmin__searchForm" onSubmit={handleUserSearch}>
              <input
                type="email"
                className="systemAdmin__searchInput"
                placeholder="Search by email..."
                value={userSearch}
                onChange={(e) => setUserSearch(e.target.value)}
              />
              <button type="submit" className="systemAdmin__searchButton">Search</button>
              {userSearch && (
                <button
                  type="button"
                  className="systemAdmin__searchButton"
                  onClick={() => { setUserSearch(''); loadUsers(); }}
                >
                  Clear
                </button>
              )}
            </form>
            <table className="systemAdmin__table">
              <thead>
                <tr>
                  <th>Email</th>
                  <th>Workspace</th>
                  <th>Provider</th>
                  <th>Admin</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map(user => (
                  <tr key={user.userId}>
                    <td>{user.email}</td>
                    <td>{user.workspaceName}</td>
                    <td>{user.identityProvider}</td>
                    <td>
                      <input
                        type="checkbox"
                        checked={user.isSystemAdministrator}
                        onChange={() => handleToggleAdmin(user.userId, user.isSystemAdministrator)}
                      />
                    </td>
                    <td>{new Date(user.createdAt).toLocaleDateString()}</td>
                    <td>
                      <button
                        className="systemAdmin__actionButton systemAdmin__actionButton--danger"
                        onClick={() => handleDeleteUser(user.userId, user.email)}
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {!loading && activeTab === 'templates' && (
          <div className="systemAdmin__section">
            <div className="systemAdmin__sectionHeader">
              <h2 className="systemAdmin__sectionTitle">System Templates ({templates.length})</h2>
              {!isEditingTemplate && (
                <button className="systemAdmin__addButton" onClick={handleAddTemplateClick}>
                  + New Template
                </button>
              )}
            </div>

            {isEditingTemplate && (
              <form className="systemAdmin__templateForm" onSubmit={handleSaveTemplate}>
                <div className="systemAdmin__field">
                  <label className="systemAdmin__label">Template Name *</label>
                  <input
                    type="text"
                    className="systemAdmin__input"
                    value={templateForm.name}
                    onChange={(e) => setTemplateForm(prev => ({ ...prev, name: e.target.value }))}
                    placeholder="e.g., Laptop, Book, Vinyl Record"
                    autoFocus
                  />
                </div>
                <div className="systemAdmin__field">
                  <label className="systemAdmin__label">Description</label>
                  <textarea
                    className="systemAdmin__textarea"
                    value={templateForm.description}
                    onChange={(e) => setTemplateForm(prev => ({ ...prev, description: e.target.value }))}
                    placeholder="Describe what this template is for"
                    rows={2}
                  />
                </div>
                <div className="systemAdmin__field">
                  <label className="systemAdmin__label">Properties</label>
                  <div className="systemAdmin__properties">
                    {templateForm.properties.map((prop, index) => (
                      <div key={index} className="systemAdmin__propertyRow">
                        <input
                          type="text"
                          className="systemAdmin__input"
                          value={prop.category}
                          onChange={(e) => handlePropertyChange(index, 'category', e.target.value)}
                          placeholder="Category"
                        />
                        <input
                          type="text"
                          className="systemAdmin__input"
                          value={prop.name}
                          onChange={(e) => handlePropertyChange(index, 'name', e.target.value)}
                          placeholder="Property Name"
                        />
                        <button
                          type="button"
                          className="systemAdmin__removeButton"
                          onClick={() => handleRemoveProperty(index)}
                        >
                          ×
                        </button>
                      </div>
                    ))}
                    <button
                      type="button"
                      className="systemAdmin__addPropertyButton"
                      onClick={handleAddProperty}
                    >
                      + Add Property
                    </button>
                  </div>
                </div>
                <div className="systemAdmin__formActions">
                  <button type="submit" className="systemAdmin__button systemAdmin__button--primary">
                    {editingTemplate ? 'Save Changes' : 'Create Template'}
                  </button>
                  <button
                    type="button"
                    className="systemAdmin__button"
                    onClick={handleCancelTemplateEdit}
                  >
                    Cancel
                  </button>
                </div>
              </form>
            )}

            {!isEditingTemplate && (
              <table className="systemAdmin__table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Description</th>
                    <th>Properties</th>
                    <th>Created</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {templates.map(template => (
                    <tr key={template.itemTemplateId}>
                      <td>{template.name}</td>
                      <td>{template.description || '—'}</td>
                      <td>{template.properties.length}</td>
                      <td>{new Date(template.createdAt).toLocaleDateString()}</td>
                      <td>
                        <button
                          className="systemAdmin__actionButton"
                          onClick={() => handleEditTemplateClick(template)}
                        >
                          Edit
                        </button>
                        <button
                          className="systemAdmin__actionButton systemAdmin__actionButton--danger"
                          onClick={() => handleDeleteTemplate(template.itemTemplateId, template.name)}
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                  {templates.length === 0 && (
                    <tr>
                      <td colSpan={5} className="systemAdmin__emptyMessage">
                        No system templates defined. Create one to make it available to all users.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            )}
          </div>
        )}

        {!loading && activeTab === 'support' && (
          <div className="systemAdmin__section">
            <h2 className="systemAdmin__sectionTitle">Support Requests</h2>
            <AdminSupportSection />
          </div>
        )}
      </div>
    </div>
  );
}

export default SystemAdmin;
