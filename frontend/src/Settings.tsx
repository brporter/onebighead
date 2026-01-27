import { useState, useEffect, useCallback } from 'react';
import { ResizableBox } from 'react-resizable';
import 'react-resizable/css/styles.css';
import './styles/Settings.css';
import { useData } from './DataContext';
import { exportApi } from './api';
import ItemTemplateEditor from './ItemTemplateEditor';
import VisibilityToggle from './VisibilityToggle';
import CollectionSetupWizard from './CollectionSetupWizard';
import type { Collection } from './types';

interface SettingsProps {
  isOpen: boolean;
  onClose: () => void;
}

function Settings({ isOpen, onClose }: SettingsProps) {
  const { collections, addCollection, updateCollection, deleteCollection, loadCollections } = useData();
  const [isAdding, setIsAdding] = useState(false);
  const [showSetupWizard, setShowSetupWizard] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [size, setSize] = useState({ width: 700, height: 600 });
  const [isResizing, setIsResizing] = useState(false);
  const [formData, setFormData] = useState({ name: '', description: '', heroImageUrl: '', isPublic: false });
  const [originalFormData, setOriginalFormData] = useState({ name: '', description: '', heroImageUrl: '', isPublic: false });
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const [showTemplateEditor, setShowTemplateEditor] = useState(false);
  const [templateEditorDirty, setTemplateEditorDirty] = useState(false);

  const hasUnsavedChanges = useCallback(() => {
    if (showTemplateEditor && templateEditorDirty) return true;
    if (!isAdding && editingId === null) return false;
    return (
      formData.name !== originalFormData.name ||
      formData.description !== originalFormData.description ||
      formData.heroImageUrl !== originalFormData.heroImageUrl ||
      formData.isPublic !== originalFormData.isPublic
    );
  }, [showTemplateEditor, templateEditorDirty, isAdding, editingId, formData, originalFormData]);

  const confirmAndClose = useCallback(() => {
    if (hasUnsavedChanges()) {
      if (confirm('You have unsaved changes. Discard them?')) {
        onClose();
      }
    } else {
      onClose();
    }
  }, [hasUnsavedChanges, onClose]);

  // Reset state when modal closes
  useEffect(() => {
    if (!isOpen) {
      setIsAdding(false);
      setEditingId(null);
      setError(null);
      setExportError(null);
      setShowTemplateEditor(false);
      setTemplateEditorDirty(false);
      setShowSetupWizard(false);
    }
  }, [isOpen]);

  // Handle escape key to close modal
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape' && isOpen) {
        e.preventDefault();
        confirmAndClose();
      }
    }
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, confirmAndClose]);

  // Prevent body scroll when modal is open
  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }
    return () => {
      document.body.style.overflow = '';
    };
  }, [isOpen]);

  if (!isOpen) return null;

  const handleAddClick = () => {
    // Use setup wizard for new collections
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

  function handleBackdropClick(e: React.MouseEvent) {
    if (e.target === e.currentTarget && !isResizing) {
      confirmAndClose();
    }
  }

  return (
    <div className="settings-modal" onClick={handleBackdropClick}>
      <ResizableBox
        width={size.width}
        height={size.height}
        minConstraints={[320, 300]}
        maxConstraints={[window.innerWidth * 0.9, window.innerHeight * 0.9]}
        onResizeStart={() => setIsResizing(true)}
        onResizeStop={(_e, { size: newSize }) => {
          setSize({ width: newSize.width, height: newSize.height });
          setTimeout(() => setIsResizing(false), 0);
        }}
        resizeHandles={['se']}
        className="settings-modal__resizable"
      >
        <div className="settings-modal__container">
          <div className="settings-modal__header">
            <h2 className="settings-modal__title">Settings</h2>
            <button className="settings-modal__close" onClick={confirmAndClose} aria-label="Close settings">
              ×
            </button>
          </div>
          <div className="settings-modal__body">
            {showSetupWizard ? (
              <CollectionSetupWizard
                onComplete={handleWizardComplete}
                onCancel={handleWizardCancel}
                isModal={true}
              />
            ) : showTemplateEditor ? (
              <ItemTemplateEditor 
                onClose={() => setShowTemplateEditor(false)} 
                onDirtyChange={setTemplateEditorDirty}
              />
            ) : (
            <>
              <section className="settings__section">
                <div className="settings__sectionHeader">
                  <h3 className="settings__sectionTitle">Collections</h3>
                  {!isEditing && (
                    <button className="settings__addButton" onClick={handleAddClick}>
                      + New Collection
                    </button>
                  )}
                </div>

                {error && <div className="settings__error">{error}</div>}

                {isEditing && (
                  <form className="settings__form" onSubmit={handleSubmit}>
                    <div className="settings__field">
                      <label className="settings__label">
                        Name <span className="settings__required">*</span>
                      </label>
                      <input
                        type="text"
                        className="settings__input"
                        value={formData.name}
                        onChange={(e) => setFormData((prev) => ({ ...prev, name: e.target.value }))}
                        placeholder="My Collection"
                        autoFocus
                      />
                    </div>
                    <div className="settings__field">
                      <label className="settings__label">Description</label>
                      <textarea
                        className="settings__textarea"
                        value={formData.description}
                        onChange={(e) => setFormData((prev) => ({ ...prev, description: e.target.value }))}
                        placeholder="A brief description of this collection"
                        rows={3}
                      />
                    </div>
                    <div className="settings__field">
                      <label className="settings__label">Hero Image URL</label>
                      <input
                        type="url"
                        className="settings__input"
                        value={formData.heroImageUrl}
                        onChange={(e) => setFormData((prev) => ({ ...prev, heroImageUrl: e.target.value }))}
                        placeholder="https://example.com/image.jpg"
                      />
                    </div>
                    <div className="settings__field">
                      <VisibilityToggle
                        isPublicOverride={formData.isPublic}
                        effectiveIsPublic={formData.isPublic}
                        parentIsPublic={true}
                        onChange={(value) => setFormData((prev) => ({ ...prev, isPublic: value === true }))}
                        label="Collection Visibility"
                        isCollection={true}
                      />
                    </div>
                    <div className="settings__formActions">
                      <button
                        type="submit"
                        className="settings__button settings__button--primary"
                        disabled={isSubmitting}
                      >
                        {isSubmitting ? 'Saving...' : isAdding ? 'Create Collection' : 'Save Changes'}
                      </button>
                      <button
                        type="button"
                        className="settings__button settings__button--secondary"
                        onClick={handleCancel}
                        disabled={isSubmitting}
                      >
                        Cancel
                      </button>
                    </div>
                  </form>
                )}

                {!isEditing && (
                  <ul className="settings__list">
                    {collections.map((collection) => (
                      <li key={collection.collectionId} className="settings__listItem">
                        <div className="settings__listItemContent">
                          <span className="settings__listItemName">{collection.name}</span>
                          {collection.description && (
                            <span className="settings__listItemDescription">{collection.description}</span>
                          )}
                        </div>
                        <div className="settings__listItemActions">
                          <button
                            className="settings__listButton"
                            onClick={() => handleEditClick(collection)}
                          >
                            Edit
                          </button>
                          {collections.length > 1 && (
                            <button
                              className="settings__listButton settings__listButton--danger"
                              onClick={() => handleDelete(collection.collectionId)}
                            >
                              Delete
                            </button>
                          )}
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </section>

              <section className="settings__section">
                <div className="settings__sectionHeader">
                  <h3 className="settings__sectionTitle">Item Templates</h3>
                </div>
                <p className="settings__sectionDescription">
                  Create reusable property templates for your items.
                </p>
                <button
                  className="settings__button settings__button--secondary"
                  onClick={() => setShowTemplateEditor(true)}
                >
                  Manage Templates
                </button>
              </section>

              <section className="settings__section">
                <div className="settings__sectionHeader">
                  <h3 className="settings__sectionTitle">Data Export</h3>
                </div>
                <p className="settings__sectionDescription">
                  Download all your collections, categories, and items as a ZIP file.
                </p>
                {exportError && <div className="settings__error">{exportError}</div>}
                <button
                  className="settings__button settings__button--primary"
                  onClick={handleExport}
                  disabled={isExporting}
                >
                  {isExporting ? 'Exporting...' : 'Export Data'}
                </button>
              </section>
            </>
          )}
        </div>
        </div>
      </ResizableBox>
    </div>
  );
}

export default Settings;
