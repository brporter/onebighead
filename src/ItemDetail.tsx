import { useState } from 'react';
import ImageGallery from './ImageGallery';
import type { Item, ItemProperty, ItemImage } from './types';

interface PropertyEditorProps {
  properties: ItemProperty[];
  onChange: (properties: ItemProperty[]) => void;
}

interface ImageEditorProps {
  images: ItemImage[];
  onChange: (images: ItemImage[]) => void;
}

interface ItemDetailProps {
  item: Item | null;
  isNew?: boolean;
  onClose?: (() => void) | null;
  onSave?: ((item: Item) => void) | null;
  onDelete?: ((id: number) => void) | null;
}

function groupPropertiesByCategory(properties: ItemProperty[] | undefined): [string, ItemProperty[]][] {
  const groups = new Map<string, ItemProperty[]>();

  for (const prop of properties ?? []) {
    const category = prop.category?.trim() || 'Other';
    if (!groups.has(category)) groups.set(category, []);
    groups.get(category)!.push(prop);
  }

  return Array.from(groups.entries());
}

function PropertyEditor({ properties, onChange }: PropertyEditorProps) {
  function handlePropertyChange(index: number, field: keyof ItemProperty, value: string) {
    const updated = properties.map((prop, i) =>
      i === index ? { ...prop, [field]: value } : prop
    );
    onChange(updated);
  }

  function handleAddProperty() {
    onChange([...properties, { category: '', name: '', value: '' }]);
  }

  function handleRemoveProperty(index: number) {
    onChange(properties.filter((_, i) => i !== index));
  }

  return (
    <div className="propertyEditor">
      <label className="propertyEditor__label">Properties</label>
      {properties.map((prop, index) => (
        <div key={index} className="propertyEditor__row">
          <input
            type="text"
            className="propertyEditor__input propertyEditor__input--category"
            placeholder="Category"
            value={prop.category}
            onChange={(e) => handlePropertyChange(index, 'category', e.target.value)}
          />
          <input
            type="text"
            className="propertyEditor__input propertyEditor__input--name"
            placeholder="Name"
            value={prop.name}
            onChange={(e) => handlePropertyChange(index, 'name', e.target.value)}
          />
          <input
            type="text"
            className="propertyEditor__input propertyEditor__input--value"
            placeholder="Value"
            value={prop.value}
            onChange={(e) => handlePropertyChange(index, 'value', e.target.value)}
          />
          <button
            type="button"
            className="propertyEditor__remove"
            onClick={() => handleRemoveProperty(index)}
            aria-label="Remove property"
          >
            ×
          </button>
        </div>
      ))}
      <button
        type="button"
        className="propertyEditor__add"
        onClick={handleAddProperty}
      >
        + Add Property
      </button>
    </div>
  );
}

function ImageEditor({ images, onChange }: ImageEditorProps) {
  function handleImageChange(index: number, field: keyof ItemImage, value: string) {
    const updated = images.map((img, i) =>
      i === index ? { ...img, [field]: value } : img
    );
    onChange(updated);
  }

  function handleAddImage() {
    onChange([...images, { url: '', alt: '' }]);
  }

  function handleRemoveImage(index: number) {
    onChange(images.filter((_, i) => i !== index));
  }

  return (
    <div className="imageEditor">
      <label className="imageEditor__label">Images</label>
      {images.map((img, index) => (
        <div key={index} className="imageEditor__row">
          <input
            type="url"
            className="imageEditor__input imageEditor__input--url"
            placeholder="Image URL"
            value={img.url}
            onChange={(e) => handleImageChange(index, 'url', e.target.value)}
          />
          <input
            type="text"
            className="imageEditor__input imageEditor__input--alt"
            placeholder="Alt text"
            value={img.alt}
            onChange={(e) => handleImageChange(index, 'alt', e.target.value)}
          />
          <button
            type="button"
            className="imageEditor__remove"
            onClick={() => handleRemoveImage(index)}
            aria-label="Remove image"
          >
            ×
          </button>
        </div>
      ))}
      <button
        type="button"
        className="imageEditor__add"
        onClick={handleAddImage}
      >
        + Add Image
      </button>
    </div>
  );
}

function ItemDetail({
  item,
  isNew = false,
  onClose,
  onSave,
  onDelete,
}: ItemDetailProps) {
  const [isEditing, setIsEditing] = useState(isNew);
  const [formData, setFormData] = useState<Item>(() => item ?? {
    id: null,
    tenantId: 1,
    categoryId: null,
    name: '',
    summary: '',
    description: '',
    properties: [],
    images: [],
  });

  if (!item && !isNew) {
    return (
      <section className="detail detail--empty">
        <p className="detail__placeholder">Select an item</p>
      </section>
    );
  }

  function handleFieldChange<K extends keyof Item>(field: K, value: Item[K]) {
    setFormData((prev) => ({ ...prev, [field]: value }));
  }

  function handleSave() {
    if (onSave) {
      onSave(formData);
    }
    if (!isNew) {
      setIsEditing(false);
    }
  }

  function handleCancel() {
    if (isNew) {
      if (onClose) onClose();
    } else {
      if (item) setFormData(item);
      setIsEditing(false);
    }
  }

  function handleDelete() {
    if (item && window.confirm(`Are you sure you want to delete "${item.name}"?`)) {
      if (onDelete && item.id !== null) onDelete(item.id);
    }
  }

  const propertyGroups = groupPropertiesByCategory(isEditing ? formData.properties : item?.properties);

  // Edit mode view
  if (isEditing) {
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
              onClick={handleCancel}
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

  // View mode
  return (
    <section className="detail">
      <div className="detail__header">
        <h2 className="detail__title">{item?.name}</h2>
        <div className="detail__headerActions">
          <button
            type="button"
            className="detail__btn detail__btn--secondary"
            onClick={() => setIsEditing(true)}
          >
            Edit
          </button>
          {onClose && (
            <button type="button" className="detail__close" onClick={onClose}>
              Back to list
            </button>
          )}
        </div>
      </div>

      <p className="detail__description">{item?.description}</p>

      <ImageGallery key={item?.id ?? 'new'} images={item?.images} title={item?.name} />

      {propertyGroups.length ? (
        <div className="detail__properties">
          {propertyGroups.map(([category, props]) => (
            <section key={category} className="detail__property-group">
              <h3 className="detail__property-group-title">{category}</h3>
              <dl className="detail__property-group-list">
                {props.map(({ name, value }) => (
                  <div key={`${category}:${name}`} className="detail__property-row">
                    <dt className="detail__property-name">{name}</dt>
                    <dd className="detail__property-value">{value}</dd>
                  </div>
                ))}
              </dl>
            </section>
          ))}
        </div>
      ) : null}
    </section>
  );
}

export default ItemDetail;

