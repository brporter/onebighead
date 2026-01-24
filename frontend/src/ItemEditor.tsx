import { useState } from 'react';
import PropertyEditor from './PropertyEditor';
import ImageEditor from './ImageEditor';
import CategorySelector from './CategorySelector';
import type { Item, Category, ItemProperty } from './types';

interface ItemEditorProps {
  item: Item | null;
  categories: Category[];
  onSave: (item: Item) => void;
  onCancel: () => void;
  onDelete?: ((id: number) => void) | null;
  initialProperties?: ItemProperty[];
}

function ItemEditor({
  item,
  categories,
  onSave,
  onCancel,
  onDelete,
  initialProperties,
}: ItemEditorProps) {
  const [formData, setFormData] = useState<Item>(() => item ?? {
    id: null,
    tenantId: 1,
    collectionId: 0,
    categoryId: null,
    name: '',
    summary: '',
    description: '',
    properties: initialProperties ?? [],
    images: [],
  });

  const isNew = formData.id === null;

  function handleFieldChange<K extends keyof Item>(field: K, value: Item[K]) {
    setFormData((prev) => ({ ...prev, [field]: value }));
  }

  function handleSave() {
    onSave(formData);
  }

  function handleDelete() {
    if (item && window.confirm(`Are you sure you want to delete "${item.name}"?`)) {
      if (onDelete && item.id !== null) onDelete(item.id);
    }
  }

  return (
    <section className="detail detail--editing">
      <form className="detail__form" onSubmit={(e) => e.preventDefault()}>
        <div className="detail__header">
          <h2 className="detail__title">
            {isNew ? 'Add New Item' : `Edit: ${item?.name}`}
          </h2>
        </div>

        <div className="detail__field">
          <label htmlFor="item-name" className="detail__label">Name</label>
          <input
            id="item-name"
            type="text"
            className="detail__input"
            value={formData.name}
            onChange={(e) => handleFieldChange('name', e.target.value)}
            placeholder="Item name"
            required
            autoComplete="off"
          />
        </div>

        <div className="detail__field">
          <label htmlFor="item-summary" className="detail__label">Summary</label>
          <input
            id="item-summary"
            type="text"
            className="detail__input"
            value={formData.summary}
            onChange={(e) => handleFieldChange('summary', e.target.value)}
            placeholder="Brief summary"
          />
        </div>

        <div className="detail__field">
          <label htmlFor="item-description" className="detail__label">Description</label>
          <textarea
            id="item-description"
            className="detail__textarea"
            value={formData.description}
            onChange={(e) => handleFieldChange('description', e.target.value)}
            placeholder="Full description"
            rows={4}
          />
        </div>

        <CategorySelector
          categories={categories}
          selectedCategoryId={formData.categoryId}
          onChange={(categoryId) => handleFieldChange('categoryId', categoryId)}
        />

        <PropertyEditor
          properties={formData.properties || []}
          onChange={(props) => handleFieldChange('properties', props)}
        />

        <ImageEditor
          images={formData.images || []}
          onChange={(imgs) => handleFieldChange('images', imgs)}
        />

        <div className="detail__actions">
          <button
            type="button"
            className="detail__btn detail__btn--primary"
            onClick={handleSave}
            disabled={!formData.name?.trim()}
          >
            {isNew ? 'Create Item' : 'Save Changes'}
          </button>
          <button
            type="button"
            className="detail__btn detail__btn--secondary"
            onClick={onCancel}
          >
            Cancel
          </button>
          {!isNew && onDelete && (
            <button
              type="button"
              className="detail__btn detail__btn--danger"
              onClick={handleDelete}
            >
              Delete
            </button>
          )}
        </div>
      </form>
    </section>
  );
}

export default ItemEditor;

