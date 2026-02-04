import { useState, useEffect, useCallback, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import '../styles/App.css';
import '../styles/SettingsView.css';
import { useData } from '../contexts/DataContext';
import { useUser } from '../contexts/UserContext';
import { exportApi, tenantsApi } from '../api';
import ItemTemplateEditor from '../components/template/ItemTemplateEditor';
import CollectionTemplateEditor from '../components/collection/CollectionTemplateEditor';
import VisibilityToggle from '../components/common/VisibilityToggle';
import CollectionSetupWizard from '../components/collection/CollectionSetupWizard';
import TenantSetupWizard from '../components/wizard/TenantSetupWizard';
import { SupportSection } from '../components/support/SupportSection';
import { AccountDeletionSection, UserButton, UserManagement } from '../components/user';
import { SupportModal } from '../components/support/SupportModal';
import { TenantEditModal, TenantDeletionSection } from '../components/tenant';
import { SiteHeader, SiteFooter } from '../components/common';
import type { Collection, TenantMembership } from '../utils/types';
import { Visibility, TenantRole } from '../utils/types';

type SettingsSection = 'collections' | 'templates' | 'team' | 'tenants' | 'export' | 'support' | 'account';

function SettingsView() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { user } = useUser();
  const { collections, addCollection, updateCollection, deleteCollection, loadCollections } = useData();
  
  // Initialize section from URL query param or default to collections
  const initialSection = (searchParams.get('section') as SettingsSection) || 'collections';
  const [activeSection, setActiveSection] = useState<SettingsSection>(
    ['collections', 'templates', 'team', 'tenants', 'export', 'support', 'account'].includes(initialSection) ? initialSection : 'collections'
  );

  // Tenant management state
  const [isCreatingTenant, setIsCreatingTenant] = useState(false);
  const [tenantError, setTenantError] = useState<string | null>(null);
  const [isLeavingTenant, setIsLeavingTenant] = useState<number | null>(null);
  const [editingTenant, setEditingTenant] = useState<TenantMembership | null>(null);
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
          {!isEditing && user?.isTenantAdmin && (
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
                  {collections.length > 1 && user?.isTenantAdmin && (
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

  const handleTenantSetupComplete = () => {
    setIsCreatingTenant(false);
    // Reload to refresh user context with new tenant, returning to My Tenants section
    window.location.href = '/settings?section=tenants';
  };

  const handleTenantSetupCancel = () => {
    setIsCreatingTenant(false);
  };

  const handleLeaveTenant = async (tenant: TenantMembership) => {
    if (!confirm(`Are you sure you want to leave "${tenant.tenantName}"? You will lose access to all data in this tenant.`)) {
      return;
    }

    setIsLeavingTenant(tenant.tenantId);
    setTenantError(null);
    try {
      await tenantsApi.leave(tenant.tenantId);
      // Reload to refresh user context
      window.location.reload();
    } catch (err) {
      setTenantError(err instanceof Error ? err.message : 'Failed to leave tenant');
      setIsLeavingTenant(null);
    }
  };

  const handleSwitchTenant = async (tenant: TenantMembership) => {
    try {
      await tenantsApi.switch(tenant.tenantId);
      window.location.reload();
    } catch (err) {
      setTenantError(err instanceof Error ? err.message : 'Failed to switch tenant');
    }
  };

  const renderTenantsSection = () => {
    const tenants = user?.tenants || [];
    const activeTenant = user?.activeTenant;
    const canLeaveTenant = (tenant: TenantMembership) => {
      // Cannot leave if it's the only tenant
      if (tenants.length <= 1) return false;
      // Cannot leave if you're the only admin (would need to check server-side, but we'll let API handle it)
      return true;
    };

    // Show the tenant setup wizard
    if (isCreatingTenant) {
      return (
        <TenantSetupWizard
          showTerms={false}
          isWelcome={false}
          onComplete={handleTenantSetupComplete}
          onCancel={handleTenantSetupCancel}
        />
      );
    }

    return (
      <div className="settings-section">
        <div className="settings-section__header">
          <div>
            <h2 className="settings-section__title">My Tenants</h2>
            <p className="settings-section__description">
              Manage your tenant memberships. You can belong to multiple tenants and switch between them.
            </p>
          </div>
          <button
            className="settings-section__addButton"
            onClick={() => setIsCreatingTenant(true)}
          >
            + Create New Workspace
          </button>
        </div>

        {tenantError && <div className="settings-section__error">{tenantError}</div>}

        <div className="settings-tenant-list">
          {tenants.map((tenant) => (
            <div
              key={tenant.tenantId}
              className={`settings-tenant-card ${tenant.tenantId === activeTenant?.tenantId ? 'settings-tenant-card--active' : ''}`}
            >
              <div className="settings-tenant-card__content">
                <div className="settings-tenant-card__header">
                  <h3 className="settings-tenant-card__name">{tenant.tenantName}</h3>
                  {tenant.tenantId === activeTenant?.tenantId && (
                    <span className="settings-tenant-card__badge settings-tenant-card__badge--current">Current</span>
                  )}
                  <span className={`settings-tenant-card__badge ${tenant.tenantRole === TenantRole.TenantAdmin ? 'settings-tenant-card__badge--admin' : ''}`}>
                    {tenant.tenantRole === TenantRole.TenantAdmin ? 'Admin' : 'Member'}
                  </span>
                </div>
                {!tenant.hasCompletedWelcome && (
                  <p className="settings-tenant-card__status">Setup not completed</p>
                )}
              </div>
              <div className="settings-tenant-card__actions">
                {tenant.tenantRole === TenantRole.TenantAdmin && (
                  <button
                    className="settings-tenant-card__button"
                    onClick={() => setEditingTenant(tenant)}
                  >
                    Edit
                  </button>
                )}
                {tenant.tenantId !== activeTenant?.tenantId && (
                  <button
                    className="settings-tenant-card__button"
                    onClick={() => handleSwitchTenant(tenant)}
                  >
                    Switch
                  </button>
                )}
                {canLeaveTenant(tenant) && tenant.tenantRole !== TenantRole.TenantAdmin && (
                  <button
                    className="settings-tenant-card__button settings-tenant-card__button--danger"
                    onClick={() => handleLeaveTenant(tenant)}
                    disabled={isLeavingTenant === tenant.tenantId}
                  >
                    {isLeavingTenant === tenant.tenantId ? 'Leaving...' : 'Leave'}
                  </button>
                )}
                {tenant.tenantRole === TenantRole.TenantAdmin && (
                  <TenantDeletionSection
                    tenant={tenant}
                    onDeleted={() => window.location.reload()}
                  />
                )}
              </div>
            </div>
          ))}
        </div>
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
      case 'collections':
        return renderCollectionsSection();
      case 'templates':
        return renderTemplatesSection();
      case 'team':
        return renderTeamSection();
      case 'tenants':
        return renderTenantsSection();
      case 'export':
        return renderExportSection();
      case 'support':
        return renderSupportSection();
      case 'account':
        return renderAccountSection();
      default:
        return renderCollectionsSection();
    }
  };

  const navItems = useMemo(() => {
    const items: { id: SettingsSection; label: string; icon: string }[] = [
      { id: 'collections', label: 'Collections', icon: '📚' },
    ];

    // Admin-only sections
    if (user?.isTenantAdmin) {
      items.push(
        { id: 'templates', label: 'Item Templates', icon: '📋' },
        { id: 'team', label: 'Team Members', icon: '👥' },
        { id: 'export', label: 'Data Export', icon: '📦' }
      );
    }

    // My Tenants is always visible (user can manage their memberships)
    items.push({ id: 'tenants', label: 'My Tenants', icon: '🏢' });

    // Support is always visible
    items.push({ id: 'support', label: 'Support', icon: '💬' });

    // Account is always visible
    items.push({ id: 'account', label: 'Account', icon: '👤' });

    return items;
  }, [user?.isTenantAdmin]);

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

      <TenantEditModal
        tenant={editingTenant}
        isOpen={editingTenant !== null}
        onClose={() => setEditingTenant(null)}
        onSaved={() => window.location.reload()}
      />
    </div>
  );
}

export default SettingsView;
