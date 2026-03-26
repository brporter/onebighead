import { useState, useEffect } from 'react';
import type { Category } from '../../utils/types';
import CategoryTemplateSelector from './CategoryTemplateSelector';

interface CategoryManagerFormProps {
  category: Category | null;
  categories: Category[];
  collectionId: number;
  isNew: boolean;
  onSave: (updates: { name: string; description: string; parentCategoryId: number | null; itemTemplateIds: number[] }) => void;
  onDelete: (categoryId: number) => void;
  onPublish: (category: Category) => void;
  onUnpublish: (category: Category) => void;
  onCancel: () => void;
}

const RESERVED_NAMES = ['unassigned items'];

function CategoryManagerForm({
  category,
  categories,
  collectionId,
  isNew,
  onSave,
  onDelete,
  onPublish,
  onUnpublish,
  onCancel,
}: CategoryManagerFormProps) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [parentCategoryId, setParentCategoryId] = useState<number | null>(null);
  const [itemTemplateIds, setItemTemplateIds] = useState<number[]>([]);
  const [error, setError] = useState<string | null>(null);

  const isSystem = category?.isSystem ?? false;
  const isPublic = category?.effectiveIsPublic ?? false;

  // Reset form when category changes or switching to create mode
  useEffect(() => {
    if (isNew) {
      setName('');
      setDescription('');
      setParentCategoryId(null);
      setItemTemplateIds([]);
      setError(null);
    } else if (category) {
      setName(category.name);
      setDescription(category.description);
      setParentCategoryId(category.parentCategoryId);
      setItemTemplateIds(category.itemTemplateIds);
      setError(null);
    }
  }, [category, isNew]);

  // Get available parent categories (exclude self and descendants to prevent circular references)
  const getAvailableParents = (): Category[] => {
    if (isNew || !category) {
      return categories.filter((c) => !c.isSystem);
    }

    // Build set of this category and all its descendants
    const excludeIds = new Set<number>();
    excludeIds.add(category.categoryId);

    const findDescendants = (parentId: number) => {
      for (const c of categories) {
        if (c.parentCategoryId === parentId && !excludeIds.has(c.categoryId)) {
          excludeIds.add(c.categoryId);
          findDescendants(c.categoryId);
        }
      }
    };
    findDescendants(category.categoryId);

    return categories.filter((c) => !excludeIds.has(c.categoryId) && !c.isSystem);
  };

  const validateName = (value: string): string | null => {
    const trimmed = value.trim();
    if (!trimmed) {
      return 'Name is required';
    }
    if (RESERVED_NAMES.includes(trimmed.toLowerCase())) {
      return `"${trimmed}" is a reserved name and cannot be used`;
    }
    return null;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    const nameError = validateName(name);
    if (nameError) {
      setError(nameError);
      return;
    }

    onSave({
      name: name.trim(),
      description: description.trim(),
      parentCategoryId,
      itemTemplateIds,
    });
  };

  const handleDelete = () => {
    if (!category || isSystem) return;
    onDelete(category.categoryId);
  };

  // Empty state: no category selected and not creating new
  if (!category && !isNew) {
    return (
      <div className="category-manager-form category-manager-form--empty">
        <p>Select a category to edit, or click + to add a new one.</p>
      </div>
    );
  }

  // System category: read-only view
  if (category && isSystem) {
    return (
      <div className="category-manager-form">
        <div className="category-manager-form__header">
          <h3>{category.name}</h3>
        </div>
        <p className="modal__info">System categories cannot be modified.</p>
        <div className="modal__field">
          <label className="modal__label">Name</label>
          <input
            type="text"
            className="modal__input"
            value={name}
            disabled
          />
        </div>
        <div className="modal__field">
          <label className="modal__label">Description</label>
          <textarea
            className="modal__textarea"
            value={description}
            disabled
            rows={3}
          />
        </div>
      </div>
    );
  }

  const availableParents = getAvailableParents();

  return (
    <div className="category-manager-form">
      {category && (
        <div className="category-manager-form__header">
          <h3>{category.name}</h3>
          <span className={`category-manager-form__badge category-manager-form__badge--${isPublic ? 'public' : 'private'}`}>
            {isPublic ? 'Public' : 'Private'}
          </span>
        </div>
      )}

      <form onSubmit={handleSubmit}>
        {error && (
          <div className="modal__error" role="alert">
            {error}
          </div>
        )}

        <div className="modal__field">
          <label htmlFor="category-name" className="modal__label">
            Name <span className="modal__required">*</span>
          </label>
          <input
            id="category-name"
            type="text"
            className="modal__input"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Category name"
            required
          />
        </div>

        <div className="modal__field">
          <label htmlFor="category-description" className="modal__label">
            Description
          </label>
          <textarea
            id="category-description"
            className="modal__textarea"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Optional description"
            rows={3}
          />
        </div>

        <div className="modal__field">
          <label htmlFor="category-parent" className="modal__label">
            Parent Category
          </label>
          <select
            id="category-parent"
            className="modal__select"
            value={parentCategoryId ?? ''}
            onChange={(e) => setParentCategoryId(e.target.value ? Number(e.target.value) : null)}
          >
            <option value="">None (root level)</option>
            {availableParents.map((c) => (
              <option key={c.categoryId} value={c.categoryId}>
                {c.name}
              </option>
            ))}
          </select>
        </div>

        <div className="modal__field">
          <label className="modal__label">
            Recommended Templates
          </label>
          <CategoryTemplateSelector
            collectionId={collectionId}
            selectedTemplateIds={itemTemplateIds}
            onChange={setItemTemplateIds}
          />
        </div>

        {category && !isNew && (
          <div className="modal__field">
            <label className="modal__label">Visibility</label>
            <div className="category-manager-form__visibility">
              <span className="category-manager-form__visibility-text">
                {isPublic ? 'Public' : 'Private'}
              </span>
              {isPublic ? (
                <button
                  type="button"
                  className="modal__button modal__button--secondary"
                  onClick={() => onUnpublish(category)}
                >
                  Unpublish
                </button>
              ) : (
                <button
                  type="button"
                  className="modal__button modal__button--primary"
                  onClick={() => onPublish(category)}
                >
                  Publish
                </button>
              )}
            </div>
          </div>
        )}

        <div className="category-manager-form__footer">
          {category && !isNew && (
            <button
              type="button"
              className="modal__button modal__button--danger"
              onClick={handleDelete}
            >
              Delete
            </button>
          )}
          <div className="category-manager-form__footer-right">
            <button
              type="button"
              className="modal__button modal__button--secondary"
              onClick={onCancel}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="modal__button modal__button--primary"
              disabled={!name.trim()}
            >
              {isNew ? 'Create' : 'Save Changes'}
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}

export default CategoryManagerForm;
