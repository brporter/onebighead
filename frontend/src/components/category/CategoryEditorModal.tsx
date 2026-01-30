import { useState, useEffect, useRef } from 'react';
import type { Category } from '../../utils/types';
import { useData } from '../../contexts/DataContext';
import VisibilityToggle from '../common/VisibilityToggle';
import CategoryTemplateSelector from './CategoryTemplateSelector';

interface CategoryEditorModalProps {
  category: Category | null; // null = creating new category
  isOpen: boolean;
  onClose: () => void;
  onSaved?: () => void;
}

const RESERVED_NAMES = ['unassigned items'];

function CategoryEditorModal({ category, isOpen, onClose, onSaved }: CategoryEditorModalProps) {
  const { categories, currentCollection, addCategory, updateCategory, deleteCategory } = useData();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [parentCategoryId, setParentCategoryId] = useState<number | null>(null);
  const [isPublicOverride, setIsPublicOverride] = useState<boolean | null>(null);
  const [itemTemplateIds, setItemTemplateIds] = useState<number[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const dialogRef = useRef<HTMLDialogElement>(null);

  const isNew = category === null;
  const isSystem = category?.isSystem ?? false;

  // Control dialog open/close
  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;

    if (isOpen) {
      dialog.showModal();
    } else {
      dialog.close();
    }
  }, [isOpen]);

  // Handle native dialog close (e.g., Escape key)
  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;

    const handleClose = () => {
      onClose();
    };

    dialog.addEventListener('close', handleClose);
    return () => dialog.removeEventListener('close', handleClose);
  }, [onClose]);

  // Reset form when modal opens or category changes
  useEffect(() => {
    if (isOpen) {
      setName(category?.name ?? '');
      setDescription(category?.description ?? '');
      setParentCategoryId(category?.parentCategoryId ?? null);
      setIsPublicOverride(category?.isPublicOverride ?? null);
      setItemTemplateIds(category?.itemTemplateIds ?? []);
      setError(null);
    }
  }, [isOpen, category]);

  // Get available parent categories (exclude self and descendants to prevent circular references)
  const getAvailableParents = (): Category[] => {
    if (isNew) {
      return categories.filter((c) => !c.isSystem);
    }

    // Build set of this category and all its descendants
    const excludeIds = new Set<number>();
    excludeIds.add(category!.categoryId);

    const findDescendants = (parentId: number) => {
      for (const c of categories) {
        if (c.parentCategoryId === parentId && !excludeIds.has(c.categoryId)) {
          excludeIds.add(c.categoryId);
          findDescendants(c.categoryId);
        }
      }
    };
    findDescendants(category!.categoryId);

    return categories.filter((c) => !excludeIds.has(c.categoryId) && !c.isSystem);
  };

  // Determine if parent allows public override
  const getParentIsPublic = (): boolean => {
    if (!currentCollection?.isPublic) return false;
    if (parentCategoryId === null) return true;
    const parent = categories.find((c) => c.categoryId === parentCategoryId);
    return parent?.effectiveIsPublic ?? true;
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

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    const nameError = validateName(name);
    if (nameError) {
      setError(nameError);
      return;
    }

    setIsSubmitting(true);
    setError(null);

    try {
      if (isNew) {
        if (!currentCollection) {
          setError('No collection selected');
          return;
        }
        await addCategory({
          collectionId: currentCollection.collectionId,
          name: name.trim(),
          description: description.trim(),
          parentCategoryId,
          isPublicOverride,
          itemTemplateIds,
        });
      } else {
        await updateCategory(category!.categoryId, {
          name: name.trim(),
          description: description.trim(),
          parentCategoryId,
          isPublicOverride,
          itemTemplateIds,
        });
      }
      onSaved?.();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDelete = async () => {
    if (!category || isSystem) return;

    if (!window.confirm(`Are you sure you want to delete "${category.name}"? Items in this category will be moved to "Unassigned Items".`)) {
      return;
    }

    setIsSubmitting(true);
    setError(null);

    try {
      await deleteCategory(category.categoryId);
      onSaved?.();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleBackdropClick = (e: React.MouseEvent<HTMLDialogElement>) => {
    if (e.target === dialogRef.current) {
      onClose();
    }
  };

  const availableParents = getAvailableParents();

  return (
    <dialog ref={dialogRef} className="modal-dialog" onClick={handleBackdropClick}>
      <div className="modal">
        <div className="modal__header">
          <h2 className="modal__title">
            {isSystem ? category?.name : isNew ? 'Add Category' : `Edit: ${category?.name}`}
          </h2>
          <button
            type="button"
            className="modal__close"
            onClick={onClose}
            aria-label="Close"
          >
            ×
          </button>
        </div>

        {isSystem ? (
          <div className="modal__body">
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
        ) : (
          <form className="modal__body" onSubmit={handleSubmit}>
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
                autoFocus
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
              <VisibilityToggle
                isPublicOverride={isPublicOverride}
                effectiveIsPublic={category?.effectiveIsPublic ?? (currentCollection?.isPublic ?? false)}
                parentIsPublic={getParentIsPublic()}
                onChange={(value) => setIsPublicOverride(value)}
                label="Visibility"
              />
            </div>

            {currentCollection && (
              <div className="modal__field">
                <label className="modal__label">
                  Recommended Templates
                </label>
                <CategoryTemplateSelector
                  collectionId={currentCollection.collectionId}
                  selectedTemplateIds={itemTemplateIds}
                  onChange={setItemTemplateIds}
                  disabled={isSubmitting}
                />
              </div>
            )}

            <div className="modal__actions">
              <button
                type="submit"
                className="detail__btn detail__btn--primary"
                disabled={isSubmitting || !name.trim()}
              >
                {isSubmitting ? 'Saving...' : isNew ? 'Create' : 'Save'}
              </button>
              <button
                type="button"
                className="detail__btn detail__btn--secondary"
                onClick={onClose}
                disabled={isSubmitting}
              >
                Cancel
              </button>
              {!isNew && (
                <button
                  type="button"
                  className="detail__btn detail__btn--danger"
                  onClick={handleDelete}
                  disabled={isSubmitting}
                >
                  Delete
                </button>
              )}
            </div>
          </form>
        )}

        {isSystem && (
          <div className="modal__actions">
            <button
              type="button"
              className="detail__btn detail__btn--secondary"
              onClick={onClose}
            >
              Close
            </button>
          </div>
        )}
      </div>
    </dialog>
  );
}

export default CategoryEditorModal;

