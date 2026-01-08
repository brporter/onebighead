import { useState } from 'react';
import './styles/Settings.css';
import BackNav from './BackNav';
import { useData } from './DataContext';
import type { Collection } from './types';

interface SettingsProps {
  onBack: () => void;
}

function Settings({ onBack }: SettingsProps) {
  const { collections, addCollection, updateCollection, deleteCollection, loadCollections } = useData();
  const [isAdding, setIsAdding] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [formData, setFormData] = useState({ name: '', description: '', heroImageUrl: '' });
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleAddClick = () => {
    setFormData({ name: '', description: '', heroImageUrl: '' });
    setIsAdding(true);
    setEditingId(null);
    setError(null);
  };

  const handleEditClick = (collection: Collection) => {
    setFormData({
      name: collection.name,
      description: collection.description || '',
      heroImageUrl: collection.heroImageUrl || '',
    });
    setEditingId(collection.collectionId);
    setIsAdding(false);
    setError(null);
  };

  const handleCancel = () => {
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
          formData.heroImageUrl.trim() || undefined
        );
      } else if (editingId !== null) {
        await updateCollection(editingId, {
          name: formData.name.trim(),
          description: formData.description.trim() || undefined,
          heroImageUrl: formData.heroImageUrl.trim() || undefined,
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

  const isEditing = isAdding || editingId !== null;

  return (
    <div className="settings">
      <BackNav label="Back" onClick={onBack} />
      <div className="settings__content">
        <h2 className="settings__title">Settings</h2>
        
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
      </div>
    </div>
  );
}

export default Settings;
