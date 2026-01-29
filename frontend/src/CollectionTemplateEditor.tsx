import { useState, useEffect, useCallback } from 'react';
import { useData } from './DataContext';
import type { ItemTemplate, Collection } from './types';

interface CollectionTemplateEditorProps {
  collection: Collection;
  onClose: () => void;
  onDirtyChange?: (isDirty: boolean) => void;
}

function CollectionTemplateEditor({ collection, onClose, onDirtyChange }: CollectionTemplateEditorProps) {
  const { loadCollectionTemplates, loadItemTemplates, itemTemplates, associateTemplateWithCollection, disassociateTemplateFromCollection } = useData();
  const [collectionTemplateIds, setCollectionTemplateIds] = useState<Set<number>>(new Set());
  const [originalTemplateIds, setOriginalTemplateIds] = useState<Set<number>>(new Set());
  const [allTemplates, setAllTemplates] = useState<ItemTemplate[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Load templates on mount
  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const [colTemplates] = await Promise.all([
          loadCollectionTemplates(collection.collectionId),
          loadItemTemplates(),
        ]);
        
        const templateIds = new Set(colTemplates.map(t => t.itemTemplateId));
        setCollectionTemplateIds(templateIds);
        setOriginalTemplateIds(new Set(templateIds));
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load templates');
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, [collection.collectionId, loadCollectionTemplates, loadItemTemplates]);

  // Combine and deduplicate templates
  useEffect(() => {
    const combined = [...itemTemplates];
    combined.sort((a, b) => a.name.localeCompare(b.name));
    setAllTemplates(combined);
  }, [itemTemplates]);

  // Track dirty state
  const isDirty = useCallback(() => {
    if (collectionTemplateIds.size !== originalTemplateIds.size) return true;
    for (const id of collectionTemplateIds) {
      if (!originalTemplateIds.has(id)) return true;
    }
    return false;
  }, [collectionTemplateIds, originalTemplateIds]);

  useEffect(() => {
    onDirtyChange?.(isDirty());
  }, [isDirty, onDirtyChange]);

  const handleToggleTemplate = (templateId: number) => {
    setCollectionTemplateIds(prev => {
      const next = new Set(prev);
      if (next.has(templateId)) {
        next.delete(templateId);
      } else {
        next.add(templateId);
      }
      return next;
    });
  };

  const handleSave = async () => {
    setSaving(true);
    setError(null);

    try {
      // Find templates to add (in new set but not original)
      const toAdd = [...collectionTemplateIds].filter(id => !originalTemplateIds.has(id));
      // Find templates to remove (in original but not new set)
      const toRemove = [...originalTemplateIds].filter(id => !collectionTemplateIds.has(id));

      // Execute all changes
      await Promise.all([
        ...toAdd.map(id => associateTemplateWithCollection(collection.collectionId, id)),
        ...toRemove.map(id => disassociateTemplateFromCollection(collection.collectionId, id)),
      ]);

      // Update original to current (no longer dirty)
      setOriginalTemplateIds(new Set(collectionTemplateIds));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save changes');
    } finally {
      setSaving(false);
    }
  };

  const handleCancel = () => {
    if (isDirty()) {
      if (!confirm('You have unsaved changes. Discard them?')) {
        return;
      }
    }
    onClose();
  };

  if (loading) {
    return (
      <div className="collectionTemplateEditor">
        <div className="collectionTemplateEditor__header">
          <h3 className="collectionTemplateEditor__title">
            Templates for "{collection.name}"
          </h3>
        </div>
        <div className="collectionTemplateEditor__loading">Loading templates...</div>
      </div>
    );
  }

  return (
    <div className="collectionTemplateEditor">
      <div className="collectionTemplateEditor__header">
        <h3 className="collectionTemplateEditor__title">
          Templates for "{collection.name}"
        </h3>
      </div>

      {error && <div className="collectionTemplateEditor__error">{error}</div>}

      <p className="collectionTemplateEditor__description">
        Select which templates should be available when creating new items in this collection.
        Templates not selected here can still be used from the full template library.
      </p>

      {allTemplates.length === 0 ? (
        <p className="collectionTemplateEditor__empty">
          No templates available. Create templates in the "Item Templates" section first.
        </p>
      ) : (
        <div className="collectionTemplateEditor__list">
          {allTemplates.map((template) => (
            <label
              key={template.itemTemplateId}
              className="collectionTemplateEditor__item"
            >
              <input
                type="checkbox"
                className="collectionTemplateEditor__checkbox"
                checked={collectionTemplateIds.has(template.itemTemplateId)}
                onChange={() => handleToggleTemplate(template.itemTemplateId)}
                disabled={saving}
              />
              <div className="collectionTemplateEditor__itemContent">
                <span className="collectionTemplateEditor__itemName">{template.name}</span>
                {template.isSystem && (
                  <span className="collectionTemplateEditor__systemBadge">System</span>
                )}
                {template.description && (
                  <span className="collectionTemplateEditor__itemDescription">{template.description}</span>
                )}
                <span className="collectionTemplateEditor__propertyCount">
                  {template.properties.length} {template.properties.length === 1 ? 'property' : 'properties'}
                </span>
              </div>
            </label>
          ))}
        </div>
      )}

      <div className="collectionTemplateEditor__actions">
        <button
          className="settings__button settings__button--primary"
          onClick={handleSave}
          disabled={saving || !isDirty()}
        >
          {saving ? 'Saving...' : 'Save Changes'}
        </button>
        <button
          className="settings__button settings__button--secondary"
          onClick={handleCancel}
          disabled={saving}
        >
          {isDirty() ? 'Cancel' : 'Back'}
        </button>
      </div>
    </div>
  );
}

export default CollectionTemplateEditor;
