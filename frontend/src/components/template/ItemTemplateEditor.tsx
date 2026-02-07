import React, { useState, useEffect, useCallback } from 'react';
import { useData } from '../../contexts/DataContext';
import { SortablePropertyList, type BaseProperty, type FieldConfig } from '../common';
import '../../styles/ItemTemplateEditor.css';
import type { ItemTemplate, ItemTemplateProperty } from '../../utils/types';
import { generateUniqueId } from '../../utils/idUtils';

interface PropertyFormData extends BaseProperty {
  id: string;
  category: string;
  name: string;
}

interface ItemTemplateEditorProps {
  onClose: () => void;
  onDirtyChange?: (isDirty: boolean) => void;
  isFullPage?: boolean;
}

const FIELD_CONFIG: FieldConfig[] = [
  { field: 'category', placeholder: 'e.g., Specs, Details' },
  { field: 'name', placeholder: 'e.g., CPU, Author' },
];

const CLASS_NAMES = {
  list: 'template-form__propertyList',
  categoryGroup: 'template-form__categoryGroup',
  categoryHeader: 'template-form__categoryHeader',
  row: 'template-form__propertyRow',
  rowDragging: 'template-form__propertyRow--dragging',
  rowOverlay: 'template-form__propertyRow--overlay',
  input: 'template-form__input',
  removeButton: 'template-form__removeBtn',
};

function ItemTemplateEditor({ onDirtyChange, isFullPage = false }: ItemTemplateEditorProps) {
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
    properties: [] as PropertyFormData[],
  });
  const [originalFormData, setOriginalFormData] = useState({
    name: '',
    description: '',
    properties: [] as PropertyFormData[],
  });
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [filter, setFilter] = useState<'all' | 'system' | 'workspace'>('all');

  const hasUnsavedChanges = useCallback(() => {
    if (!isAdding && editingTemplate === null) return false;
    if (formData.name !== originalFormData.name) return true;
    if (formData.description !== originalFormData.description) return true;
    if (formData.properties.length !== originalFormData.properties.length) return true;
    for (let i = 0; i < formData.properties.length; i++) {
      if (formData.properties[i].category !== originalFormData.properties[i]?.category) return true;
      if (formData.properties[i].name !== originalFormData.properties[i]?.name) return true;
    }
    return false;
  }, [isAdding, editingTemplate, formData, originalFormData]);

  // Notify parent of dirty state changes
  useEffect(() => {
    onDirtyChange?.(hasUnsavedChanges());
  }, [hasUnsavedChanges, onDirtyChange]);

  useEffect(() => {
    // Map UI filter to API filter: 'system' -> 'shared', 'workspace' -> 'personal'
    const filterValue = filter === 'all' ? undefined : (filter === 'system' ? 'shared' : 'personal');
    loadItemTemplates(filterValue);
  }, [filter, loadItemTemplates]);

  const handleAddClick = () => {
    const initial = { name: '', description: '', properties: [] as PropertyFormData[] };
    setFormData(initial);
    setOriginalFormData(initial);
    setIsAdding(true);
    setEditingTemplate(null);
    setError(null);
  };

  const handleEditClick = (template: ItemTemplate) => {
    const initial = {
      name: template.name,
      description: template.description,
      properties: template.properties.map((p) => ({
        id: generateUniqueId('prop'),
        category: p.category,
        name: p.name,
      })),
    };
    setFormData(initial);
    setOriginalFormData(JSON.parse(JSON.stringify(initial)));
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
      properties: [...prev.properties, { id: generateUniqueId('prop'), category: '', name: '' }],
    }));
  };

  const handleRemoveProperty = (id: string) => {
    setFormData((prev) => ({
      ...prev,
      properties: prev.properties.filter((p) => p.id !== id),
    }));
  };

  const handleFieldChange = (id: string, field: keyof PropertyFormData, value: string) => {
    setFormData((prev) => ({
      ...prev,
      properties: prev.properties.map((p) => (p.id === id ? { ...p, [field]: value } : p)),
    }));
  };

  const handlePropertiesReorder = (newProperties: PropertyFormData[]) => {
    setFormData((prev) => ({
      ...prev,
      properties: newProperties,
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
  const workspaceTemplates = itemTemplates.filter((t) => !t.isSystem);
  const systemTemplates = itemTemplates.filter((t) => t.isSystem);

  // Group properties by category for display
  const groupPropertiesByCategory = (properties: ItemTemplateProperty[]) => {
    const grouped: Record<string, string[]> = {};
    properties.forEach((p) => {
      if (!grouped[p.category]) {
        grouped[p.category] = [];
      }
      grouped[p.category].push(p.name);
    });
    return grouped;
  };

  // Render the template form
  const renderForm = () => (
    <div className="template-form">
      <div className="template-form__header">
        <h3 className="template-form__title">
          {isAdding ? 'Create New Template' : `Edit: ${editingTemplate?.name}`}
        </h3>
        <button
          type="button"
          className="template-form__cancel"
          onClick={handleCancel}
          disabled={isSubmitting}
        >
          Cancel
        </button>
      </div>

      <form onSubmit={handleSubmit}>
        <div className="template-form__section">
          <h4 className="template-form__sectionTitle">Basic Information</h4>
          <div className="template-form__fields">
            <div className="template-form__field">
              <label className="template-form__label">
                Template Name <span className="template-form__required">*</span>
              </label>
              <input
                type="text"
                className="template-form__input"
                value={formData.name}
                onChange={(e) => setFormData((prev) => ({ ...prev, name: e.target.value }))}
                placeholder="e.g., Laptop, Book, Vinyl Record"
                autoFocus
              />
              <span className="template-form__hint">Give your template a clear, descriptive name</span>
            </div>
            <div className="template-form__field">
              <label className="template-form__label">Description</label>
              <textarea
                className="template-form__textarea"
                value={formData.description}
                onChange={(e) => setFormData((prev) => ({ ...prev, description: e.target.value }))}
                placeholder="Describe what types of items this template is best suited for"
                rows={2}
              />
            </div>
          </div>
        </div>

        <div className="template-form__section">
          <h4 className="template-form__sectionTitle">Properties</h4>
          <p className="template-form__sectionHint">
            Define the fields that items using this template will have. Group related properties under the same category.
          </p>

          <div className="template-form__properties">
            {formData.properties.length === 0 ? (
              <div className="template-form__emptyProperties">
                <span className="template-form__emptyIcon">📝</span>
                <p>No properties defined yet</p>
                <p className="template-form__emptyHint">Add properties to define what data items will store</p>
              </div>
            ) : (
              <>
                <div className="template-form__propertyHeader">
                  <span></span>
                  <span>Category</span>
                  <span>Property Name</span>
                  <span></span>
                </div>
                <SortablePropertyList
                  properties={formData.properties}
                  fields={FIELD_CONFIG}
                  classNames={CLASS_NAMES}
                  onPropertiesChange={handlePropertiesReorder}
                  onFieldChange={handleFieldChange}
                  onRemove={handleRemoveProperty}
                />
              </>
            )}

            <button
              type="button"
              className="template-form__addProperty"
              onClick={handleAddProperty}
            >
              <span className="template-form__addIcon">+</span>
              Add Property
            </button>
          </div>
        </div>

        {error && <div className="template-form__error">{error}</div>}

        <div className="template-form__actions">
          <button
            type="button"
            className="template-form__btn template-form__btn--secondary"
            onClick={handleCancel}
            disabled={isSubmitting}
          >
            Cancel
          </button>
          <button
            type="submit"
            className="template-form__btn template-form__btn--primary"
            disabled={isSubmitting}
          >
            {isSubmitting ? 'Saving...' : isAdding ? 'Create Template' : 'Save Changes'}
          </button>
        </div>
      </form>
    </div>
  );

  // Render a template card
  const renderTemplateCard = (template: ItemTemplate, isSystem: boolean) => {
    const grouped = groupPropertiesByCategory(template.properties);
    const categoryCount = Object.keys(grouped).length;

    return (
      <div key={template.itemTemplateId} className="template-card">
        <div className="template-card__header">
          <h4 className="template-card__name">{template.name}</h4>
          {isSystem && <span className="template-card__badge">System</span>}
        </div>

        {template.description && (
          <p className="template-card__description">{template.description}</p>
        )}

        <div className="template-card__stats">
          <span className="template-card__stat">
            <strong>{template.properties.length}</strong> properties
          </span>
          <span className="template-card__stat">
            <strong>{categoryCount}</strong> {categoryCount === 1 ? 'category' : 'categories'}
          </span>
        </div>

        {template.properties.length > 0 && (
          <div className="template-card__preview">
            {Object.entries(grouped).slice(0, 3).map(([category, props]) => (
              <div key={category} className="template-card__category">
                <span className="template-card__categoryName">{category}</span>
                <span className="template-card__props">
                  {props.slice(0, 3).join(', ')}
                  {props.length > 3 && ` +${props.length - 3} more`}
                </span>
              </div>
            ))}
            {Object.keys(grouped).length > 3 && (
              <span className="template-card__more">
                +{Object.keys(grouped).length - 3} more categories
              </span>
            )}
          </div>
        )}

        <div className="template-card__actions">
          {isSystem ? (
            <button
              className="template-card__btn"
              onClick={() => handleEditClick(template)}
              title="Create a customized copy of this template"
            >
              Customize
            </button>
          ) : (
            <>
              <button
                className="template-card__btn"
                onClick={() => handleEditClick(template)}
              >
                Edit
              </button>
              <button
                className="template-card__btn template-card__btn--danger"
                onClick={() => handleDelete(template.itemTemplateId)}
              >
                Delete
              </button>
            </>
          )}
        </div>
      </div>
    );
  };

  if (isEditing) {
    return (
      <div className={`template-editor ${isFullPage ? 'template-editor--fullpage' : ''}`}>
        {renderForm()}
      </div>
    );
  }

  return (
    <div className={`template-editor ${isFullPage ? 'template-editor--fullpage' : ''}`}>
      <div className="template-editor__header">
        <div className="template-editor__headerContent">
          <h2 className="template-editor__title">Item Templates</h2>
          <p className="template-editor__description">
            Templates define the properties available when adding items. Create custom templates or use system templates as a starting point.
          </p>
        </div>
        <button className="template-editor__addBtn" onClick={handleAddClick}>
          + New Template
        </button>
      </div>

      <div className="template-editor__filters">
        <div className="template-editor__filterGroup">
          <label className="template-editor__filterLabel">Show:</label>
          <select
            className="template-editor__filterSelect"
            value={filter}
            onChange={(e) => setFilter(e.target.value as 'all' | 'system' | 'workspace')}
          >
            <option value="all">All Templates</option>
            <option value="workspace">My Templates</option>
            <option value="system">System Templates</option>
          </select>
        </div>
      </div>

      {error && <div className="template-editor__error">{error}</div>}
      {itemTemplatesError && <div className="template-editor__error">{itemTemplatesError}</div>}

      {itemTemplatesLoading ? (
        <div className="template-editor__loading">
          <span className="template-editor__spinner"></span>
          Loading templates...
        </div>
      ) : (
        <div className="template-editor__content">
          {(filter === 'all' || filter === 'workspace') && workspaceTemplates.length > 0 && (
            <section className="template-editor__section">
              <h3 className="template-editor__sectionTitle">My Templates</h3>
              <div className="template-editor__grid">
                {workspaceTemplates.map((t) => renderTemplateCard(t, false))}
              </div>
            </section>
          )}

          {(filter === 'all' || filter === 'system') && systemTemplates.length > 0 && (
            <section className="template-editor__section">
              <h3 className="template-editor__sectionTitle">System Templates</h3>
              <div className="template-editor__grid">
                {systemTemplates.map((t) => renderTemplateCard(t, true))}
              </div>
            </section>
          )}

          {itemTemplates.length === 0 && (
            <div className="template-editor__empty">
              <span className="template-editor__emptyIcon">📋</span>
              <h3>No templates yet</h3>
              <p>Create your first template to define property schemas for your items.</p>
              <button className="template-editor__addBtn" onClick={handleAddClick}>
                + Create Template
              </button>
            </div>
          )}

          {itemTemplates.length > 0 &&
           ((filter === 'workspace' && workspaceTemplates.length === 0) ||
            (filter === 'system' && systemTemplates.length === 0)) && (
            <div className="template-editor__empty">
              <p>No {filter === 'workspace' ? 'custom' : 'system'} templates found.</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default ItemTemplateEditor;
