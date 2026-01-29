import { useState, useEffect, useCallback } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import '../styles/SettingsView.css';
import { useData } from '../DataContext';
import { useUser } from '../UserContext';
import { exportApi } from '../api';
import ItemTemplateEditor from '../ItemTemplateEditor';
import CollectionTemplateEditor from '../CollectionTemplateEditor';
import VisibilityToggle from '../VisibilityToggle';
import CollectionSetupWizard from '../CollectionSetupWizard';
import { SupportSection } from '../SupportSection';
import UserButton from '../UserButton';
import { SupportModal } from '../SupportModal';
import type { Collection } from '../types';

type SettingsSection = 'collections' | 'templates' | 'export' | 'support';

function SettingsView() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { user } = useUser();
  const { collections, addCollection, updateCollection, deleteCollection, loadCollections } = useData();
  
  // Initialize section from URL query param or default to collections
  const initialSection = (searchParams.get('section') as SettingsSection) || 'collections';
  const [activeSection, setActiveSection] = useState<SettingsSection>(
    ['collections', 'templates', 'export', 'support'].includes(initialSection) ? initialSection : 'collections'
  );
  const [isAdding, setIsAdding] = useState(false);
  const [showSetupWizard, setShowSetupWizard] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [formData, setFormData] = useState({ name: '', description: '', heroImageUrl: '', isPublic: false });
  const [originalFormData, setOriginalFormData] = useState({ name: '', description: '', heroImageUrl: '', isPublic: false });
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const [templateEditorDirty, setTemplateEditorDirty] = useState(false);
  const [isSupportOpen, setIsSupportOpen] = useState(false);
  const [editingCollectionTemplates, setEditingCollectionTemplates] = useState<Collection | null>(null);
  const [collectionTemplateEditorDirty, setCollectionTemplateEditorDirty] = useState(false);

  const hasUnsavedChanges = useCallback(() => {
    if (activeSection === 'templates' && templateEditorDirty) return true;
    if (editingCollectionTemplates && collectionTemplateEditorDirty) return true;
    if (!isAdding && editingId === null) return false;
    return (
      formData.name !== originalFormData.name ||
      formData.description !== originalFormData.description ||
      formData.heroImageUrl !== originalFormData.heroImageUrl ||
      formData.isPublic !== originalFormData.isPublic
    );
  }, [activeSection, templateEditorDirty, editingCollectionTemplates, collectionTemplateEditorDirty, isAdding, editingId, formData, originalFormData]);

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
      isPublic: collection.isPublic ?? false,
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
          formData.isPublic
        );
      } else if (editingId !== null) {
        await updateCollection(editingId, {
          name: formData.name.trim(),
          description: formData.description.trim() || undefined,
          heroImageUrl: formData.heroImageUrl.trim() || undefined,
          isPublic: formData.isPublic,
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
          {!isEditing && (
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
                isPublicOverride={formData.isPublic}
                effectiveIsPublic={formData.isPublic}
                parentIsPublic={true}
                onChange={(value) => setFormData((prev) => ({ ...prev, isPublic: value === true }))}
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
                    <span className={`settings-collection-card__visibility ${collection.isPublic ? 'settings-collection-card__visibility--public' : ''}`}>
                      {collection.isPublic ? '🌐 Public' : '🔒 Private'}
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
                  {collections.length > 1 && (
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
      <SupportSection isFullPage={true} />
    </div>
  );

  const renderContent = () => {
    switch (activeSection) {
      case 'collections':
        return renderCollectionsSection();
      case 'templates':
        return renderTemplatesSection();
      case 'export':
        return renderExportSection();
      case 'support':
        return renderSupportSection();
      default:
        return renderCollectionsSection();
    }
  };

  const navItems: { id: SettingsSection; label: string; icon: string }[] = [
    { id: 'collections', label: 'Collections', icon: '📚' },
    { id: 'templates', label: 'Item Templates', icon: '📋' },
    { id: 'export', label: 'Data Export', icon: '📦' },
    { id: 'support', label: 'Support', icon: '💬' },
  ];

  return (
    <div className="settings-page">
      <header className="settings-page__header">
        <div className="settings-page__headerContent">
          <div className="settings-page__headerLeft">
            <button 
              className="settings-page__back" 
              onClick={() => confirmAndNavigate('/collections')}
            >
              ← Back to Collections
            </button>
            <h1 className="settings-page__title">Settings</h1>
          </div>
          <div className="settings-page__headerRight">
            <button className="support-link" onClick={() => setIsSupportOpen(true)}>
              <span className="support-link__icon">?</span>
              Support
            </button>
            <UserButton />
          </div>
        </div>
      </header>

      <div className="settings-page__layout">
        <nav className="settings-nav">
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
        </nav>

        <main className="settings-page__content">
          {renderContent()}
        </main>
      </div>

      <SupportModal
        isOpen={isSupportOpen}
        onClose={() => setIsSupportOpen(false)}
        userEmail={user?.email}
      />
    </div>
  );
}

export default SettingsView;
