import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import '../styles/App.css';
import '../styles/SettingsView.css';
import { useData } from '../contexts/DataContext';
import { useUser } from '../contexts/UserContext';
import { exportApi, workspacesApi, dashboardApi } from '../api';
import type { DashboardData } from '../api';
import type { RestorableWorkspace } from '../api/workspaces';
import ItemTemplateEditor from '../components/template/ItemTemplateEditor';
import CollectionTemplateEditor from '../components/collection/CollectionTemplateEditor';
import VisibilityToggle from '../components/common/VisibilityToggle';
import CollectionSetupWizard from '../components/collection/CollectionSetupWizard';
import WorkspaceSetupWizard from '../components/wizard/WorkspaceSetupWizard';
import { SupportSection } from '../components/support/SupportSection';
import { AccountDeletionSection, UserButton, UserManagement } from '../components/user';
import { SupportModal } from '../components/support/SupportModal';
import { WorkspaceEditModal, WorkspaceDeletionSection } from '../components/workspace';
import { SiteHeader, SiteFooter } from '../components/common';
import type { Collection, WorkspaceMembership } from '../utils/types';
import { Visibility, WorkspaceRole } from '../utils/types';

type SettingsSection = 'dashboard' | 'collections' | 'templates' | 'team' | 'workspaces' | 'export' | 'support' | 'account';

function SettingsView() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { user } = useUser();
  const { collections, addCollection, updateCollection, deleteCollection, loadCollections } = useData();
  
  // Initialize section from URL query param or default to dashboard
  const initialSection = (searchParams.get('section') as SettingsSection) || 'dashboard';
  const [activeSection, setActiveSection] = useState<SettingsSection>(
    ['dashboard', 'collections', 'templates', 'team', 'workspaces', 'export', 'support', 'account'].includes(initialSection) ? initialSection : 'dashboard'
  );

  // Workspace management state
  const [isCreatingWorkspace, setIsCreatingWorkspace] = useState(false);
  const [workspaceError, setWorkspaceError] = useState<string | null>(null);
  const [isLeavingWorkspace, setIsLeavingWorkspace] = useState<number | null>(null);
  const [editingWorkspace, setEditingWorkspace] = useState<WorkspaceMembership | null>(null);
  const [deletedWorkspaces, setDeletedWorkspaces] = useState<RestorableWorkspace[]>([]);
  const [isRestoringWorkspace, setIsRestoringWorkspace] = useState<number | null>(null);
  const [isAdding, setIsAdding] = useState(false);
  const [showSetupWizard, setShowSetupWizard] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [formData, setFormData] = useState({ name: '', description: '', heroImageUrl: '', visibility: Visibility.Private });
  const [originalFormData, setOriginalFormData] = useState({ name: '', description: '', heroImageUrl: '', visibility: Visibility.Private });
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const [templateEditorDirty, setTemplateEditorDirty] = useState(false);
  const [isSupportOpen, setIsSupportOpen] = useState(false);
  const [supportRefreshKey, setSupportRefreshKey] = useState(0);
  const [editingCollectionTemplates, setEditingCollectionTemplates] = useState<Collection | null>(null);
  const [collectionTemplateEditorDirty, setCollectionTemplateEditorDirty] = useState(false);
  const [teamManagementDirty, setTeamManagementDirty] = useState(false);
  const [dashboardData, setDashboardData] = useState<DashboardData | null>(null);
  const [dashboardLoading, setDashboardLoading] = useState(false);

  // Public access state
  const [publicAccessLoading, setPublicAccessLoading] = useState(false);
  const [publicAccessSlug, setPublicAccessSlug] = useState('');
  const [publicAccessEnabled, setPublicAccessEnabled] = useState(false);
  const [publicAccessError, setPublicAccessError] = useState<string | null>(null);
  const [publicAccessSaving, setPublicAccessSaving] = useState(false);
  const [publicAccessSuccess, setPublicAccessSuccess] = useState(false);

  const hasUnsavedChanges = useCallback(() => {
    if (activeSection === 'templates' && templateEditorDirty) return true;
    if (activeSection === 'team' && teamManagementDirty) return true;
    if (editingCollectionTemplates && collectionTemplateEditorDirty) return true;
    if (!isAdding && editingId === null) return false;
    return (
      formData.name !== originalFormData.name ||
      formData.description !== originalFormData.description ||
      formData.heroImageUrl !== originalFormData.heroImageUrl ||
      formData.visibility !== originalFormData.visibility
    );
  }, [activeSection, templateEditorDirty, teamManagementDirty, editingCollectionTemplates, collectionTemplateEditorDirty, isAdding, editingId, formData, originalFormData]);

  const confirmAndNavigate = useCallback((path: string) => {
    if (hasUnsavedChanges()) {
      if (confirm('You have unsaved changes. Discard them?')) {
        navigate(path);
      }
    } else {
      navigate(path);
    }
  }, [hasUnsavedChanges, navigate]);

  // Load collections on mount
  useEffect(() => {
    loadCollections();
  }, [loadCollections]);

  // Load dashboard data when dashboard section is active
  useEffect(() => {
    if (activeSection !== 'dashboard') return;
    let cancelled = false;
    setDashboardLoading(true);
    dashboardApi.get()
      .then((data) => { if (!cancelled) setDashboardData(data); })
      .catch(() => { /* silently fail */ })
      .finally(() => { if (!cancelled) setDashboardLoading(false); });
    return () => { cancelled = true; };
  }, [activeSection]);

  // Load deleted workspaces when workspaces section is active
  useEffect(() => {
    const loadDeletedWorkspaces = async () => {
      try {
        const deleted = await workspacesApi.getRestorableWorkspaces();
        setDeletedWorkspaces(deleted);
      } catch {
        // Silently fail - deleted workspaces section is optional
      }
    };

    if (activeSection === 'workspaces') {
      loadDeletedWorkspaces();
    }
  }, [activeSection]);

  // Load public access settings when workspaces section is active and user is admin
  useEffect(() => {
    if (activeSection !== 'workspaces' || !user?.isWorkspaceAdmin || !user?.activeWorkspace) return;
    let cancelled = false;
    setPublicAccessLoading(true);
    setPublicAccessError(null);
    workspacesApi.getPublicAccess(user.activeWorkspace.workspaceId)
      .then((data) => {
        if (!cancelled) {
          setPublicAccessSlug(data.slug || '');
          setPublicAccessEnabled(data.isPublicAccessEnabled);
        }
      })
      .catch(() => {
        if (!cancelled) {
          // Auto-suggest slug from workspace name if we couldn't load
          const suggestedSlug = toSlug(user.activeWorkspace?.workspaceName || '');
          setPublicAccessSlug(suggestedSlug);
        }
      })
      .finally(() => { if (!cancelled) setPublicAccessLoading(false); });
    return () => { cancelled = true; };
  }, [activeSection, user?.isWorkspaceAdmin, user?.activeWorkspace]);

  const handleSectionChange = (section: SettingsSection) => {
    if (hasUnsavedChanges()) {
      if (!confirm('You have unsaved changes. Discard them?')) {
        return;
      }
    }
    setActiveSection(section);
    setIsAdding(false);
    setEditingId(null);
    setError(null);
    setExportError(null);
    setShowSetupWizard(false);
  };

  const handleAddClick = () => {
    setShowSetupWizard(true);
  };

  const handleWizardComplete = async () => {
    setShowSetupWizard(false);
    await loadCollections();
  };

  const handleWizardCancel = () => {
    setShowSetupWizard(false);
  };

  const handleEditClick = (collection: Collection) => {
    const initial = {
      name: collection.name,
      description: collection.description || '',
      heroImageUrl: collection.heroImageUrl || '',
      visibility: collection.visibility ?? Visibility.Private,
    };
    setFormData(initial);
    setOriginalFormData(initial);
    setEditingId(collection.collectionId);
    setIsAdding(false);
    setError(null);
  };

  const handleCancel = () => {
    if (hasUnsavedChanges()) {
      if (!confirm('You have unsaved changes. Discard them?')) {
        return;
      }
    }
    setIsAdding(false);
    setEditingId(null);
    setError(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.name.trim()) {
      setError('Name is required');
      return;
    }

    setIsSubmitting(true);
    setError(null);

    try {
      if (isAdding) {
        await addCollection(
          formData.name.trim(),
          formData.description.trim() || undefined,
          formData.heroImageUrl.trim() || undefined,
          formData.visibility
        );
      } else if (editingId !== null) {
        await updateCollection(editingId, {
          name: formData.name.trim(),
          description: formData.description.trim() || undefined,
          heroImageUrl: formData.heroImageUrl.trim() || undefined,
          visibility: formData.visibility,
        });
      }
      setIsAdding(false);
      setEditingId(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDelete = async (collectionId: number) => {
    if (!confirm('Are you sure you want to delete this collection? All items and categories within it will be permanently deleted.')) {
      return;
    }

    setError(null);
    try {
      await deleteCollection(collectionId);
      await loadCollections();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete collection');
    }
  };

  const handleExport = async () => {
    setIsExporting(true);
    setExportError(null);

    try {
      const { blob, filename } = await exportApi.downloadExport();

      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      setExportError(err instanceof Error ? err.message : 'Failed to export data');
    } finally {
      setIsExporting(false);
    }
  };

  const isEditing = isAdding || editingId !== null;

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    const value = bytes / Math.pow(1024, i);
    return `${value.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
  };

  const renderDashboardSection = () => {
    if (dashboardLoading || !dashboardData) {
      return (
        <div className="settings-section">
          <div className="settings-section__header">
            <div>
              <h2 className="settings-section__title">Dashboard</h2>
              <p className="settings-section__description">Loading workspace statistics...</p>
            </div>
          </div>
        </div>
      );
    }

    const maxView = Math.max(...dashboardData.dailyViews.map(d => d.viewCount), 1);
    const dayLabels = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

    return (
      <div className="settings-section">
        <div className="settings-section__header">
          <div>
            <h2 className="settings-section__title">Dashboard</h2>
            <p className="settings-section__description">
              Overview of your workspace activity and statistics.
            </p>
          </div>
        </div>

        <div className="dashboard-stats">
          <div className="dashboard-stats__card">
            <div className="dashboard-stats__value">{dashboardData.collectionCount}</div>
            <div className="dashboard-stats__label">Collections</div>
          </div>
          <div className="dashboard-stats__card">
            <div className="dashboard-stats__value">{dashboardData.itemCount}</div>
            <div className="dashboard-stats__label">Items</div>
          </div>
          <div className="dashboard-stats__card">
            <div className="dashboard-stats__value">{dashboardData.imageCount}</div>
            <div className="dashboard-stats__label">Images</div>
            <div className="dashboard-stats__detail">{formatBytes(dashboardData.imageTotalSizeBytes)}</div>
          </div>
        </div>

        <div className="dashboard-chart">
          <h3 className="dashboard-chart__title">Item Views (Last 7 Days)</h3>
          <div className="dashboard-chart__bars">
            {dashboardData.dailyViews.map((day) => {
              const pct = maxView > 0 ? (day.viewCount / maxView) * 100 : 0;
              const dateObj = new Date(day.date + 'T00:00:00');
              const label = dayLabels[dateObj.getDay()];
              return (
                <div key={day.date} className="dashboard-chart__bar-wrapper">
                  <div className="dashboard-chart__bar-count">{day.viewCount}</div>
                  <div className="dashboard-chart__bar-track">
                    <div
                      className="dashboard-chart__bar"
                      style={{ height: `${pct}%` }}
                    />
                  </div>
                  <div className="dashboard-chart__bar-label">{label}</div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    );
  };

  const renderCollectionsSection = () => {
    if (showSetupWizard) {
      return (
        <CollectionSetupWizard
          onComplete={handleWizardComplete}
          onCancel={handleWizardCancel}
          isModal={false}
        />
      );
    }

    // Show collection template editor if editing templates
    if (editingCollectionTemplates) {
      return (
        <div className="settings-section">
          <CollectionTemplateEditor
            collection={editingCollectionTemplates}
            onClose={() => setEditingCollectionTemplates(null)}
            onDirtyChange={setCollectionTemplateEditorDirty}
          />
        </div>
      );
    }

    return (
      <div className="settings-section">
        <div className="settings-section__header">
          <div>
            <h2 className="settings-section__title">Collections</h2>
            <p className="settings-section__description">
              Manage your collections. Each collection can have categories and items.
            </p>
          </div>
          {!isEditing && user?.isWorkspaceAdmin && (
            <button className="settings-section__addButton" onClick={handleAddClick}>
              + New Collection
            </button>
          )}
        </div>

        {error && <div className="settings-section__error">{error}</div>}

        {isEditing && (
          <form className="settings-form" onSubmit={handleSubmit}>
            <h3 className="settings-form__title">{isAdding ? 'New Collection' : 'Edit Collection'}</h3>
            <div className="settings-form__field">
              <label className="settings-form__label">
                Name <span className="settings-form__required">*</span>
              </label>
              <input
                type="text"
                className="settings-form__input"
                value={formData.name}
                onChange={(e) => setFormData((prev) => ({ ...prev, name: e.target.value }))}
                placeholder="My Collection"
                autoFocus
              />
            </div>
            <div className="settings-form__field">
              <label className="settings-form__label">Description</label>
              <textarea
                className="settings-form__textarea"
                value={formData.description}
                onChange={(e) => setFormData((prev) => ({ ...prev, description: e.target.value }))}
                placeholder="A brief description of this collection"
                rows={3}
              />
            </div>
            <div className="settings-form__field">
              <label className="settings-form__label">Hero Image URL</label>
              <input
                type="url"
                className="settings-form__input"
                value={formData.heroImageUrl}
                onChange={(e) => setFormData((prev) => ({ ...prev, heroImageUrl: e.target.value }))}
                placeholder="https://example.com/image.jpg"
              />
            </div>
            <div className="settings-form__field">
              <VisibilityToggle
                visibility={formData.visibility}
                effectiveIsPublic={formData.visibility === Visibility.Public}
                parentIsPublic={true}
                onChange={(value) => setFormData((prev) => ({ ...prev, visibility: value }))}
                label="Collection Visibility"
                isCollection={true}
              />
            </div>
            {editingId !== null && (
              <div className="settings-form__field">
                <label className="settings-form__label">Item Templates</label>
                <p className="settings-form__hint">
                  Configure which templates are available when creating items in this collection.
                </p>
                <button
                  type="button"
                  className="settings-form__button settings-form__button--secondary"
                  onClick={() => {
                    const collection = collections.find(c => c.collectionId === editingId);
                    if (collection) {
                      setEditingCollectionTemplates(collection);
                    }
                  }}
                >
                  Manage Templates
                </button>
              </div>
            )}
            <div className="settings-form__actions">
              <button
                type="submit"
                className="settings-form__button settings-form__button--primary"
                disabled={isSubmitting}
              >
                {isSubmitting ? 'Saving...' : isAdding ? 'Create Collection' : 'Save Changes'}
              </button>
              <button
                type="button"
                className="settings-form__button settings-form__button--secondary"
                onClick={handleCancel}
                disabled={isSubmitting}
              >
                Cancel
              </button>
            </div>
          </form>
        )}

        {!isEditing && (
          <div className="settings-collection-grid">
            {collections.map((collection) => (
              <div key={collection.collectionId} className="settings-collection-card">
                <div className="settings-collection-card__content">
                  <h3 className="settings-collection-card__name">{collection.name}</h3>
                  {collection.description && (
                    <p className="settings-collection-card__description">{collection.description}</p>
                  )}
                  <div className="settings-collection-card__meta">
                    <span className={`settings-collection-card__visibility ${collection.effectiveIsPublic ? 'settings-collection-card__visibility--public' : ''}`}>
                      {collection.effectiveIsPublic ? '🌐 Public' : '🔒 Private'}
                    </span>
                  </div>
                </div>
                <div className="settings-collection-card__actions">
                  <button
                    className="settings-collection-card__button"
                    onClick={() => setEditingCollectionTemplates(collection)}
                  >
                    Templates
                  </button>
                  <button
                    className="settings-collection-card__button"
                    onClick={() => handleEditClick(collection)}
                  >
                    Edit
                  </button>
                  {collections.length > 1 && user?.isWorkspaceAdmin && (
                    <button
                      className="settings-collection-card__button settings-collection-card__button--danger"
                      onClick={() => handleDelete(collection.collectionId)}
                    >
                      Delete
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    );
  };

  const renderTemplatesSection = () => (
    <div className="settings-section settings-section--templates">
      <ItemTemplateEditor 
        onClose={() => setActiveSection('collections')} 
        onDirtyChange={setTemplateEditorDirty}
        isFullPage={true}
      />
    </div>
  );

  const renderExportSection = () => (
    <div className="settings-section">
      <div className="settings-section__header">
        <div>
          <h2 className="settings-section__title">Data Export</h2>
          <p className="settings-section__description">
            Download all your collections, categories, and items as a ZIP file. This includes all metadata and can be used for backup purposes.
          </p>
        </div>
      </div>
      
      <div className="settings-export-card">
        <div className="settings-export-card__icon">📦</div>
        <div className="settings-export-card__content">
          <h3 className="settings-export-card__title">Export All Data</h3>
          <p className="settings-export-card__description">
            Creates a ZIP archive containing JSON files with all your collections, categories, items, and their properties.
          </p>
        </div>
        {exportError && <div className="settings-section__error">{exportError}</div>}
        <button
          className="settings-export-card__button"
          onClick={handleExport}
          disabled={isExporting}
        >
          {isExporting ? 'Exporting...' : 'Download Export'}
        </button>
      </div>
    </div>
  );

  const renderTeamSection = () => (
    <div className="settings-section">
      <div className="settings-section__header">
        <div>
          <h2 className="settings-section__title">Team Members</h2>
          <p className="settings-section__description">
            Invite team members to collaborate on your collections.
          </p>
        </div>
      </div>
      <UserManagement onDirtyChange={setTeamManagementDirty} />
    </div>
  );

  const handleWorkspaceSetupComplete = () => {
    setIsCreatingWorkspace(false);
    // Reload to refresh user context with new workspace, returning to My Workspaces section
    window.location.href = '/settings?section=workspaces';
  };

  const handleWorkspaceSetupCancel = () => {
    setIsCreatingWorkspace(false);
  };

  const handleLeaveWorkspace = async (workspace: WorkspaceMembership) => {
    if (!confirm(`Are you sure you want to leave "${workspace.workspaceName}"? You will lose access to all data in this workspace.`)) {
      return;
    }

    setIsLeavingWorkspace(workspace.workspaceId);
    setWorkspaceError(null);
    try {
      await workspacesApi.leave(workspace.workspaceId);
      // Reload to refresh user context
      window.location.reload();
    } catch (err) {
      setWorkspaceError(err instanceof Error ? err.message : 'Failed to leave workspace');
      setIsLeavingWorkspace(null);
    }
  };

  const handleSwitchWorkspace = async (workspace: WorkspaceMembership) => {
    try {
      await workspacesApi.switch(workspace.workspaceId);
      window.location.reload();
    } catch (err) {
      setWorkspaceError(err instanceof Error ? err.message : 'Failed to switch workspace');
    }
  };

  const handleRestoreWorkspace = async (workspaceId: number) => {
    setIsRestoringWorkspace(workspaceId);
    try {
      await workspacesApi.restoreWorkspace(workspaceId);
      // Reload the page to refresh workspace list
      window.location.reload();
    } catch (err) {
      setWorkspaceError(err instanceof Error ? err.message : 'Failed to restore workspace');
      setIsRestoringWorkspace(null);
    }
  };

  const toSlug = (name: string): string => {
    return name
      .toLowerCase()
      .replace(/[^a-z0-9-]/g, '-')
      .replace(/-+/g, '-')
      .replace(/^-|-$/g, '')
      .slice(0, 50);
  };

  const isValidSlug = (slug: string): boolean => {
    return /^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$/.test(slug) && slug.length >= 3 && slug.length <= 50;
  };

  const handlePublicAccessSave = async () => {
    if (!user?.activeWorkspace) return;

    setPublicAccessError(null);
    setPublicAccessSuccess(false);

    const slug = publicAccessSlug.trim();

    if (publicAccessEnabled && !slug) {
      setPublicAccessError('A slug is required to enable public access.');
      return;
    }

    if (slug && !isValidSlug(slug)) {
      setPublicAccessError('Slug must be 3-50 characters, lowercase letters, numbers, and hyphens only. Must start and end with a letter or number.');
      return;
    }

    setPublicAccessSaving(true);
    try {
      const result = await workspacesApi.updatePublicAccess(user.activeWorkspace.workspaceId, {
        slug: slug || null,
        isPublicAccessEnabled: publicAccessEnabled,
      });
      setPublicAccessSlug(result.slug || '');
      setPublicAccessEnabled(result.isPublicAccessEnabled);
      setPublicAccessSuccess(true);
      setTimeout(() => setPublicAccessSuccess(false), 3000);
    } catch (err) {
      setPublicAccessError(err instanceof Error ? err.message : 'Failed to update public access settings');
    } finally {
      setPublicAccessSaving(false);
    }
  };

  const renderWorkspacesSection = () => {
    const workspaces = user?.workspaces || [];
    const activeWorkspace = user?.activeWorkspace;
    const canLeaveWorkspace = () => {
      // Cannot leave if it's the only workspace
      if (workspaces.length <= 1) return false;
      // Cannot leave if you're the only admin (would need to check server-side, but we'll let API handle it)
      return true;
    };

    // Show the workspace setup wizard
    if (isCreatingWorkspace) {
      return (
        <WorkspaceSetupWizard
          showTerms={false}
          isWelcome={false}
          onComplete={handleWorkspaceSetupComplete}
          onCancel={handleWorkspaceSetupCancel}
        />
      );
    }

    return (
      <div className="settings-section">
        <div className="settings-section__header">
          <div>
            <h2 className="settings-section__title">My Workspaces</h2>
            <p className="settings-section__description">
              Manage your workspace memberships. You can belong to multiple workspaces and switch between them.
            </p>
          </div>
          <button
            className="settings-section__addButton"
            onClick={() => setIsCreatingWorkspace(true)}
          >
            + Create New Workspace
          </button>
        </div>

        {workspaceError && <div className="settings-section__error">{workspaceError}</div>}

        <div className="settings-workspace-list">
          {workspaces.map((workspace) => (
            <div
              key={workspace.workspaceId}
              className={`settings-workspace-card ${workspace.workspaceId === activeWorkspace?.workspaceId ? 'settings-workspace-card--active' : ''}`}
            >
              <div className="settings-workspace-card__content">
                <div className="settings-workspace-card__header">
                  <h3 className="settings-workspace-card__name">{workspace.workspaceName}</h3>
                  {workspace.workspaceId === activeWorkspace?.workspaceId && (
                    <span className="settings-workspace-card__badge settings-workspace-card__badge--current">Current</span>
                  )}
                  <span className={`settings-workspace-card__badge ${workspace.workspaceRole === WorkspaceRole.WorkspaceAdmin ? 'settings-workspace-card__badge--admin' : ''}`}>
                    {workspace.workspaceRole === WorkspaceRole.WorkspaceAdmin ? 'Admin' : 'Member'}
                  </span>
                </div>
                {!workspace.hasCompletedWelcome && (
                  <p className="settings-workspace-card__status">Setup not completed</p>
                )}
              </div>
              <div className="settings-workspace-card__actions">
                {workspace.workspaceRole === WorkspaceRole.WorkspaceAdmin && (
                  <button
                    className="settings-workspace-card__button"
                    onClick={() => setEditingWorkspace(workspace)}
                  >
                    Edit
                  </button>
                )}
                {workspace.workspaceId !== activeWorkspace?.workspaceId && (
                  <button
                    className="settings-workspace-card__button"
                    onClick={() => handleSwitchWorkspace(workspace)}
                  >
                    Switch
                  </button>
                )}
                {canLeaveWorkspace() && workspace.workspaceRole !== WorkspaceRole.WorkspaceAdmin && (
                  <button
                    className="settings-workspace-card__button settings-workspace-card__button--danger"
                    onClick={() => handleLeaveWorkspace(workspace)}
                    disabled={isLeavingWorkspace === workspace.workspaceId}
                  >
                    {isLeavingWorkspace === workspace.workspaceId ? 'Leaving...' : 'Leave'}
                  </button>
                )}
                {workspace.workspaceRole === WorkspaceRole.WorkspaceAdmin && (
                  <WorkspaceDeletionSection
                    workspace={workspace}
                    onDeleted={() => window.location.reload()}
                  />
                )}
              </div>
            </div>
          ))}
        </div>

        {user?.isWorkspaceAdmin && (
          <>
            <div className="settings-section__divider" />
            <h3 className="settings-section__subtitle">Public Access</h3>
            <p className="settings-section__description">
              Configure public access to allow anyone to view your workspace's public collections without signing in.
            </p>

            {publicAccessLoading ? (
              <div className="settings-public-access">
                <p className="settings-public-access__loading">Loading public access settings...</p>
              </div>
            ) : (
              <div className="settings-public-access">
                {publicAccessError && (
                  <div className="settings-section__error">{publicAccessError}</div>
                )}
                {publicAccessSuccess && (
                  <div className="settings-public-access__success">Public access settings saved successfully.</div>
                )}

                <div className="settings-form__field">
                  <label className="settings-form__label" htmlFor="public-slug">
                    Public URL Slug
                  </label>
                  <input
                    id="public-slug"
                    type="text"
                    className="settings-form__input"
                    value={publicAccessSlug}
                    onChange={(e) => {
                      const val = e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, '');
                      setPublicAccessSlug(val);
                      setPublicAccessError(null);
                      setPublicAccessSuccess(false);
                    }}
                    placeholder="my-workspace"
                    maxLength={50}
                  />
                  <p className="settings-form__hint">
                    Lowercase letters, numbers, and hyphens only. 3-50 characters.
                  </p>
                </div>

                <div className="settings-form__field">
                  <label className="settings-public-access__toggle-label">
                    <input
                      type="checkbox"
                      checked={publicAccessEnabled}
                      onChange={(e) => {
                        setPublicAccessEnabled(e.target.checked);
                        setPublicAccessError(null);
                        setPublicAccessSuccess(false);
                      }}
                      disabled={!publicAccessSlug.trim()}
                    />
                    <span>Enable Public Access</span>
                  </label>
                  {!publicAccessSlug.trim() && (
                    <p className="settings-form__hint">Set a slug above to enable public access.</p>
                  )}
                </div>

                {publicAccessEnabled && publicAccessSlug.trim() && (
                  <div className="settings-public-access__preview">
                    <span className="settings-public-access__preview-label">Public URL:</span>
                    <code className="settings-public-access__preview-url">/public/{publicAccessSlug.trim()}</code>
                  </div>
                )}

                <div className="settings-form__actions">
                  <button
                    className="settings-form__button settings-form__button--primary"
                    onClick={handlePublicAccessSave}
                    disabled={publicAccessSaving}
                  >
                    {publicAccessSaving ? 'Saving...' : 'Save Public Access Settings'}
                  </button>
                </div>
              </div>
            )}
          </>
        )}

        {deletedWorkspaces.length > 0 && (
          <>
            <div className="settings-section__divider" />
            <h3 className="settings-section__subtitle">Deleted Workspaces</h3>
            <p className="settings-section__description">
              These workspaces are scheduled for permanent deletion. Restore them to keep your data.
            </p>
            <div className="settings-workspace-list">
              {deletedWorkspaces.map((workspace) => (
                <div key={workspace.workspaceId} className="settings-workspace-card settings-workspace-card--deleted">
                  <div className="settings-workspace-card__content">
                    <div className="settings-workspace-card__header">
                      <h3 className="settings-workspace-card__name">{workspace.name}</h3>
                      <span className="settings-workspace-card__badge settings-workspace-card__badge--deleted">
                        Deleted
                      </span>
                    </div>
                    <p className="settings-workspace-card__stats">
                      {workspace.stats.collectionCount} collections, {workspace.stats.itemCount} items
                    </p>
                    <p className="settings-workspace-card__countdown">
                      {workspace.daysRemaining} days until permanent deletion
                    </p>
                  </div>
                  <div className="settings-workspace-card__actions">
                    <button
                      className="settings-workspace-card__button settings-workspace-card__button--primary"
                      onClick={() => handleRestoreWorkspace(workspace.workspaceId)}
                      disabled={isRestoringWorkspace === workspace.workspaceId}
                    >
                      {isRestoringWorkspace === workspace.workspaceId ? 'Restoring...' : 'Restore'}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    );
  };

  const renderSupportSection = () => (
    <div className="settings-section settings-section--support">
      <div className="settings-section__header">
        <div>
          <h2 className="settings-section__title">Support Requests</h2>
          <p className="settings-section__description">
            View and manage your support requests. Get help with any issues you encounter.
          </p>
        </div>
      </div>
      <SupportSection
        isFullPage={true}
        onNewRequest={() => setIsSupportOpen(true)}
        refreshKey={supportRefreshKey}
      />
    </div>
  );

  const renderAccountSection = () => (
    <div className="settings-section">
      <div className="settings-section__header">
        <div>
          <h2 className="settings-section__title">Account</h2>
          <p className="settings-section__description">
            Manage your account settings and preferences.
          </p>
        </div>
      </div>

      <div className="settings-account-info">
        <div className="settings-account-info__row">
          <span className="settings-account-info__label">Email:</span>
          <span className="settings-account-info__value">{user?.email}</span>
        </div>
      </div>

      <div className="settings-section__divider" />

      <AccountDeletionSection />
    </div>
  );

  const renderContent = () => {
    switch (activeSection) {
      case 'dashboard':
        return renderDashboardSection();
      case 'collections':
        return renderCollectionsSection();
      case 'templates':
        return renderTemplatesSection();
      case 'team':
        return renderTeamSection();
      case 'workspaces':
        return renderWorkspacesSection();
      case 'export':
        return renderExportSection();
      case 'support':
        return renderSupportSection();
      case 'account':
        return renderAccountSection();
      default:
        return renderDashboardSection();
    }
  };

  const navItems = useMemo(() => {
    const items: { id: SettingsSection; label: string; icon: string }[] = [
      { id: 'dashboard', label: 'Dashboard', icon: '📊' },
      { id: 'collections', label: 'Collections', icon: '📚' },
    ];

    // Admin-only sections
    if (user?.isWorkspaceAdmin) {
      items.push(
        { id: 'templates', label: 'Item Templates', icon: '📋' },
        { id: 'team', label: 'Team Members', icon: '👥' },
        { id: 'export', label: 'Data Export', icon: '📦' }
      );
    }

    // My Workspaces is always visible (user can manage their memberships)
    items.push({ id: 'workspaces', label: 'My Workspaces', icon: '🏢' });

    // Support is always visible
    items.push({ id: 'support', label: 'Support', icon: '💬' });

    // Account is always visible
    items.push({ id: 'account', label: 'Account', icon: '👤' });

    return items;
  }, [user?.isWorkspaceAdmin]);

  return (
    <div className="app">
      <SiteHeader>
        <button className="support-link support-link--icon" onClick={() => setIsSupportOpen(true)} title="Support" aria-label="Support">
          <span className="support-link__icon">?</span>
        </button>
        <UserButton />
      </SiteHeader>

      <div className="app__layout">
        <nav className="app__sidebar" aria-label="Settings navigation">
          <div className="settings-nav">
            <ul className="settings-nav__list">
              {navItems.map((item) => (
                <li key={item.id}>
                  <button
                    className={`settings-nav__item ${activeSection === item.id ? 'settings-nav__item--active' : ''}`}
                    onClick={() => handleSectionChange(item.id)}
                  >
                    <span className="settings-nav__icon">{item.icon}</span>
                    <span className="settings-nav__label">{item.label}</span>
                  </button>
                </li>
              ))}
            </ul>
          </div>
        </nav>

        <main className="app__content settings-content">
          <div className="settings-title-bar">
            <h1 className="settings-title-bar__title">Settings</h1>
            <button className="settings-title-bar__back" onClick={() => confirmAndNavigate('/collections')}>
              Back to Collections →
            </button>
          </div>
          <div className="settings-panel">
            {renderContent()}
          </div>
        </main>
      </div>

      <SiteFooter />

      <SupportModal
        isOpen={isSupportOpen}
        onClose={() => setIsSupportOpen(false)}
        onSuccess={() => setSupportRefreshKey((k) => k + 1)}
        userEmail={user?.email}
      />

      <WorkspaceEditModal
        workspace={editingWorkspace}
        isOpen={editingWorkspace !== null}
        onClose={() => setEditingWorkspace(null)}
        onSaved={() => window.location.reload()}
      />
    </div>
  );
}

export default SettingsView;
