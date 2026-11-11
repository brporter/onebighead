import React, { useState, useEffect, useId } from 'react';
import type { Category } from '../../utils/types';
import { Visibility } from '../../utils/types';
import { availableCategoryParents, validateCategoryName, type CategoryDraft } from '../../data/categories/categoryDraft';
import CategoryTemplateSelector from './CategoryTemplateSelector';
import CategorySelector from './CategorySelector';

interface CategoryManagerFormProps {
  category: Category | null;
  categories: Category[];
  collectionId: number;
  isNew: boolean;
  initialName?: string;
  onSave: (updates: CategoryDraft) => void;
  disabled?: boolean;
  onBack: () => void;
  onPublish: (category: Category) => void;
  onUnpublish: (category: Category) => void;
  onHasChanges?: (hasChanges: boolean) => void;
  formId?: string;
}

function CategoryManagerForm(props: CategoryManagerFormProps) {
  const key = props.isNew ? `new:${props.initialName ?? ''}` : props.category?.categoryId ?? 'empty';
  return <CategoryForm key={key} {...props} />;
}

function CategoryForm({
  category,
  categories,
  collectionId,
  isNew,
  initialName = '',
  onSave,
  onBack,
  onPublish,
  onUnpublish,
  onHasChanges,
  formId,
  disabled = false,
}: CategoryManagerFormProps) {
  const inputId = useId();
  const [baseline] = useState(category);
  const [name, setName] = useState(isNew ? initialName : category?.name ?? '');
  const [description, setDescription] = useState(isNew ? '' : category?.description ?? '');
  const [parentCategoryId, setParentCategoryId] = useState<number | null>(isNew ? null : category?.parentCategoryId ?? null);
  const [itemTemplateIds, setItemTemplateIds] = useState<number[]>(isNew ? [] : category?.itemTemplateIds ?? []);
  const [error, setError] = useState<string | null>(null);

  const isSystem = category?.isSystem ?? false;
  const isPublic = category?.visibility === Visibility.Public;

  // Track whether form has unsaved changes
  const hasChanges = isNew
    ? name.trim() !== '' || description.trim() !== '' || parentCategoryId !== null || itemTemplateIds.length > 0
    : baseline
      ? name !== baseline.name || description !== baseline.description || parentCategoryId !== baseline.parentCategoryId || JSON.stringify(itemTemplateIds) !== JSON.stringify(baseline.itemTemplateIds)
      : false;

  useEffect(() => {
    onHasChanges?.(hasChanges);
  }, [hasChanges, onHasChanges]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    if (disabled || isSystem) return;
    const nameError = validateCategoryName(name);
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

  // Transient state before auto-selection
  if (!category && !isNew) {
    return <div className="category-manager-form" />;
  }

  // System category: read-only view
  if (category && isSystem) {
    return (
      <div className="category-manager-form">
        <button
          type="button"
          className="category-manager-form__back"
          onClick={onBack}
        disabled={disabled}
        >
          ← Back to Categories
        </button>
        <div className="category-manager-form__header">
          <h3>{category.name}</h3>
        </div>
        <p className="modal__info">System categories cannot be modified.</p>
        <div className="modal__field">
          <label htmlFor={`${inputId}-name`} className="modal__label">Name</label>
          <input
            id={`${inputId}-name`}
            type="text"
            className="modal__input"
            value={name}
            disabled
          />
        </div>
        <div className="modal__field">
          <label htmlFor={`${inputId}-description`} className="modal__label">Description</label>
          <textarea
            id={`${inputId}-description`}
            className="modal__textarea"
            value={description}
            disabled
            rows={3}
          />
        </div>
      </div>
    );
  }

  const availableParents = availableCategoryParents(categories, collectionId, isNew ? null : category);

  return (
    <div className="category-manager-form">
      <button
        type="button"
        className="category-manager-form__back"
        onClick={onBack}
        disabled={disabled}
      >
        ← Back to Categories
      </button>
      {category && (
        <div className="category-manager-form__header">
          <h3>{category.name}</h3>
          <span className={`category-manager-form__badge category-manager-form__badge--${isPublic ? 'public' : 'private'}`}>
            {isPublic ? 'Public' : 'Private'}
          </span>
        </div>
      )}

      <form id={formId} aria-label="Category details" onSubmit={handleSubmit}>
        <fieldset className="category-manager-form__fields" disabled={disabled}>
          {error && (
            <div className="modal__error" role="alert">
              {error}
            </div>
          )}

          <div className="modal__field">
            <label htmlFor={`${inputId}-name`} className="modal__label">
              Name <span className="modal__required">*</span>
            </label>
            <input
              id={`${inputId}-name`}
              autoFocus
              type="text"
              className="modal__input"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Category name"
              required
            />
          </div>

          <div className="modal__field">
            <label htmlFor={`${inputId}-description`} className="modal__label">
              Description
            </label>
            <textarea
              id={`${inputId}-description`}
              className="modal__textarea"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Optional description"
              rows={3}
            />
          </div>

          <CategorySelector categories={availableParents} selectedCategoryId={parentCategoryId} onChange={setParentCategoryId}
            label="Parent Category" nullLabel="None (root level)" variant="modal" />

          <div className="modal__field">
            <label className="modal__label">
              Recommended Templates
            </label>
            <CategoryTemplateSelector
              collectionId={collectionId}
              selectedTemplateIds={itemTemplateIds}
              onChange={setItemTemplateIds}
              disabled={disabled}
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

        </fieldset>
      </form>
    </div>
  );
}

export default CategoryManagerForm;
