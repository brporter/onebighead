import { useState, useEffect } from 'react';
import { useData } from './DataContext';
import type { ItemTemplate, ItemTemplateProperty } from './types';

interface ItemTemplateEditorProps {
  onClose: () => void;
}

function ItemTemplateEditor({ onClose }: ItemTemplateEditorProps) {
  const {
    itemTemplates,
    itemTemplatesLoading,
    itemTemplatesError,
    loadItemTemplates,
    createItemTemplate,
    updateItemTemplate,
    deleteItemTemplate,
  } = useData();

  const [editingTemplate, setEditingTemplate] = useState<ItemTemplate | null>(null);
  const [isAdding, setIsAdding] = useState(false);
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    properties: [] as { category: string; name: string }[],
  });
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [filter, setFilter] = useState<'all' | 'shared' | 'personal'>('all');

  useEffect(() => {
    const filterValue = filter === 'all' ? undefined : filter;
    loadItemTemplates(filterValue);
  }, [filter, loadItemTemplates]);

  const handleAddClick = () => {
    setFormData({ name: '', description: '', properties: [] });
    setIsAdding(true);
    setEditingTemplate(null);
    setError(null);
  };

  const handleEditClick = (template: ItemTemplate) => {
    setFormData({
      name: template.name,
      description: template.description,
      properties: template.properties.map((p) => ({ category: p.category, name: p.name })),
    });
    setEditingTemplate(template);
    setIsAdding(false);
    setError(null);
  };

  const handleCancel = () => {
    setIsAdding(false);
    setEditingTemplate(null);
    setError(null);
  };

  const handleAddProperty = () => {
    setFormData((prev) => ({
      ...prev,
      properties: [...prev.properties, { category: '', name: '' }],
    }));
  };

  const handleRemoveProperty = (index: number) => {
    setFormData((prev) => ({
      ...prev,
      properties: prev.properties.filter((_, i) => i !== index),
    }));
  };

  const handlePropertyChange = (index: number, field: 'category' | 'name', value: string) => {
    setFormData((prev) => ({
      ...prev,
      properties: prev.properties.map((p, i) => (i === index ? { ...p, [field]: value } : p)),
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.name.trim()) {
      setError('Name is required');
      return;
    }

    // Validate properties
    const invalidProps = formData.properties.filter((p) => !p.category.trim() || !p.name.trim());
    if (invalidProps.length > 0) {
      setError('All properties must have a category and name');
      return;
    }

    setIsSubmitting(true);
    setError(null);

    try {
      const request = {
        name: formData.name.trim(),
        description: formData.description.trim(),
        properties: formData.properties.map((p) => ({
          category: p.category.trim(),
          name: p.name.trim(),
        })),
      };

      if (isAdding) {
        await createItemTemplate(request);
      } else if (editingTemplate) {
        await updateItemTemplate(editingTemplate.itemTemplateId, request);
      }
      setIsAdding(false);
      setEditingTemplate(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDelete = async (templateId: number) => {
    if (!confirm('Are you sure you want to delete this template?')) {
      return;
    }

    try {
      await deleteItemTemplate(templateId);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete template');
    }
  };

  const isEditing = isAdding || editingTemplate !== null;
  const personalTemplates = itemTemplates.filter((t) => !t.isShared);
  const sharedTemplates = itemTemplates.filter((t) => t.isShared);

  return (
    <div className="templateEditor">
      <div className="templateEditor__header">
        <button className="templateEditor__back" onClick={onClose}>
          ← Back to Settings
        </button>
        <h3 className="templateEditor__title">Item Templates</h3>
      </div>

      {!isEditing && (
        <div className="templateEditor__controls">
          <div className="templateEditor__filter">
            <label className="templateEditor__filterLabel">Show:</label>
            <select
              className="templateEditor__filterSelect"
              value={filter}
              onChange={(e) => setFilter(e.target.value as 'all' | 'shared' | 'personal')}
            >
              <option value="all">All Templates</option>
              <option value="personal">My Templates</option>
              <option value="shared">Shared Templates</option>
            </select>
          </div>
          <button className="settings__addButton" onClick={handleAddClick}>
            + New Template
          </button>
        </div>
      )}

      {error && <div className="settings__error">{error}</div>}
      {itemTemplatesError && <div className="settings__error">{itemTemplatesError}</div>}

      {isEditing && (
        <form className="settings__form" onSubmit={handleSubmit}>
          <div className="settings__field">
            <label className="settings__label">
              Template Name <span className="settings__required">*</span>
            </label>
            <input
              type="text"
              className="settings__input"
              value={formData.name}
              onChange={(e) => setFormData((prev) => ({ ...prev, name: e.target.value }))}
              placeholder="e.g., Laptop, Book, Vinyl Record"
              autoFocus
            />
          </div>
          <div className="settings__field">
            <label className="settings__label">Description</label>
            <textarea
              className="settings__textarea"
              value={formData.description}
              onChange={(e) => setFormData((prev) => ({ ...prev, description: e.target.value }))}
              placeholder="Describe what this template is for"
              rows={2}
            />
          </div>

          <div className="settings__field">
            <label className="settings__label">Properties</label>
            <div className="templateEditor__properties">
              {formData.properties.map((prop, index) => (
                <div key={index} className="templateEditor__propertyRow">
                  <input
                    type="text"
                    className="settings__input templateEditor__categoryInput"
                    value={prop.category}
                    onChange={(e) => handlePropertyChange(index, 'category', e.target.value)}
                    placeholder="Category (e.g., Hardware)"
                  />
                  <input
                    type="text"
                    className="settings__input templateEditor__nameInput"
                    value={prop.name}
                    onChange={(e) => handlePropertyChange(index, 'name', e.target.value)}
                    placeholder="Property Name (e.g., CPU)"
                  />
                  <button
                    type="button"
                    className="templateEditor__removeButton"
                    onClick={() => handleRemoveProperty(index)}
                    aria-label="Remove property"
                  >
                    ×
                  </button>
                </div>
              ))}
              <button
                type="button"
                className="templateEditor__addPropertyButton"
                onClick={handleAddProperty}
              >
                + Add Property
              </button>
            </div>
          </div>

          <div className="settings__formActions">
            <button
              type="submit"
              className="settings__button settings__button--primary"
              disabled={isSubmitting}
            >
              {isSubmitting ? 'Saving...' : isAdding ? 'Create Template' : 'Save Changes'}
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

      {!isEditing && itemTemplatesLoading && (
        <p className="templateEditor__loading">Loading templates...</p>
      )}

      {!isEditing && !itemTemplatesLoading && (
        <>
          {(filter === 'all' || filter === 'personal') && personalTemplates.length > 0 && (
            <div className="templateEditor__section">
              <h4 className="templateEditor__sectionTitle">My Templates</h4>
              <ul className="settings__list">
                {personalTemplates.map((template) => (
                  <li key={template.itemTemplateId} className="settings__listItem">
                    <div className="settings__listItemContent">
                      <span className="settings__listItemName">{template.name}</span>
                      <span className="settings__listItemDescription">
                        {template.properties.length} properties
                        {template.description && ` • ${template.description}`}
                      </span>
                    </div>
                    <div className="settings__listItemActions">
                      <button
                        className="settings__listButton"
                        onClick={() => handleEditClick(template)}
                      >
                        Edit
                      </button>
                      <button
                        className="settings__listButton settings__listButton--danger"
                        onClick={() => handleDelete(template.itemTemplateId)}
                      >
                        Delete
                      </button>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {(filter === 'all' || filter === 'shared') && sharedTemplates.length > 0 && (
            <div className="templateEditor__section">
              <h4 className="templateEditor__sectionTitle">Shared Templates</h4>
              <ul className="settings__list">
                {sharedTemplates.map((template) => (
                  <li key={template.itemTemplateId} className="settings__listItem">
                    <div className="settings__listItemContent">
                      <span className="settings__listItemName">{template.name}</span>
                      <span className="settings__listItemDescription">
                        {template.properties.length} properties
                        {template.description && ` • ${template.description}`}
                      </span>
                    </div>
                    <div className="settings__listItemActions">
                      <span className="templateEditor__sharedBadge">Shared</span>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {itemTemplates.length === 0 && (
            <p className="templateEditor__empty">
              No templates found. Create one to define property schemas for your items.
            </p>
          )}
        </>
      )}
    </div>
  );
}

export default ItemTemplateEditor;
