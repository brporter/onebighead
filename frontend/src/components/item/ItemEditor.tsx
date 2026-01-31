import { useState } from 'react';
import PropertyEditor from './PropertyEditor';
import ImageEditor from '../common/ImageEditor';
import CategorySelector from '../category/CategorySelector';
import VisibilityToggle from '../common/VisibilityToggle';
import type { Item, Category, ItemProperty, Collection } from '../../utils/types';
import { UserFlag, Visibility } from '../../utils/types';

interface ItemEditorProps {
  item: Item | null;
  categories: Category[];
  collection: Collection | null;
  onSave: (item: Item) => void;
  onCancel: () => void;
  onDelete?: ((id: number) => void) | null;
  initialProperties?: ItemProperty[];
}

function ItemEditor({
  item,
  categories,
  collection,
  onSave,
  onCancel,
  onDelete,
  initialProperties,
}: ItemEditorProps) {
  const [formData, setFormData] = useState<Item>(() => {
    if (item) {
      // Ensure userFlag has a default value even if not present in loaded item
      return {
        ...item,
        userFlag: item.userFlag ?? UserFlag.None,
      };
    }
    return {
      id: null,
      tenantId: 1,
      collectionId: 0,
      categoryId: null,
      name: '',
      summary: '',
      description: '',
      properties: initialProperties ?? [],
      images: [],
      visibility: Visibility.Default,
      effectiveIsPublic: false,
      userFlag: UserFlag.None,
    };
  });

  const isNew = formData.id === null;

  // Determine if parent allows public override
  const getParentIsPublic = (): boolean => {
    if (!collection?.effectiveIsPublic) return false;
    if (formData.categoryId === null) return true;
    const category = categories.find((c) => c.categoryId === formData.categoryId);
    return category?.effectiveIsPublic ?? true;
  };

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

        <div className="detail__field">
          <VisibilityToggle
            visibility={formData.visibility}
            effectiveIsPublic={formData.effectiveIsPublic}
            parentIsPublic={getParentIsPublic()}
            onChange={(value) => handleFieldChange('visibility', value)}
            label="Visibility"
          />
        </div>

        <fieldset className="detail__fieldset">
          <legend className="detail__legend">My Relationship to This Item</legend>
          <div className="detail__radioGroup">
            <label className="detail__radioLabel">
              <input
                type="radio"
                name="userFlag"
                className="detail__radioInput"
                checked={formData.userFlag === UserFlag.None}
                onChange={() => handleFieldChange('userFlag', UserFlag.None)}
              />
              <span className="detail__radioText">None</span>
            </label>
            <label className="detail__radioLabel">
              <input
                type="radio"
                name="userFlag"
                className="detail__radioInput"
                checked={formData.userFlag === UserFlag.Have}
                onChange={() => handleFieldChange('userFlag', UserFlag.Have)}
              />
              <span className="detail__radioText">I Have This</span>
            </label>
            <label className="detail__radioLabel">
              <input
                type="radio"
                name="userFlag"
                className="detail__radioInput"
                checked={formData.userFlag === UserFlag.Want}
                onChange={() => handleFieldChange('userFlag', UserFlag.Want)}
              />
              <span className="detail__radioText">I Want This</span>
            </label>
            <label className="detail__radioLabel">
              <input
                type="radio"
                name="userFlag"
                className="detail__radioInput"
                checked={formData.userFlag === UserFlag.TradeOrSell}
                onChange={() => handleFieldChange('userFlag', UserFlag.TradeOrSell)}
              />
              <span className="detail__radioText">For Trade/Sale</span>
            </label>
          </div>
        </fieldset>

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

