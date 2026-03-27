import React, { useState, useEffect, useRef, useCallback } from 'react';
import type { Category } from '../../utils/types';
import type { UnpublishPreviewResponse } from '../../utils/types';
import { useData } from '../../contexts/useData';
import { useToast } from '../../contexts/useToast';
import { buildPublishToastMessage, buildPublishToastDetails, buildUnpublishToastMessage } from '../../utils/publishToastUtils';
import CategoryManagerTree from './CategoryManagerTree';
import CategoryManagerForm from './CategoryManagerForm';
import { PublishConfirmModal } from '../common/PublishConfirmModal';
import { UnpublishConfirmModal } from '../common/UnpublishConfirmModal';
import { SlugSetupModal } from '../common/SlugSetupModal';
import './CategoryManagerModal.css';

interface CategoryManagerModalProps {
  collectionId: number;
  isOpen: boolean;
  onClose: () => void;
}

function CategoryManagerModal({ collectionId, isOpen, onClose }: CategoryManagerModalProps) {
  const {
    categories,
    loadCategoriesForCollection,
    addCategory,
    updateCategory,
    deleteCategory,
    reorderCategories,
    publishCategory,
    unpublishCategory,
    getUnpublishCategoryPreview,
  } = useData();
  const { showToast } = useToast();

  const dialogRef = useRef<HTMLDialogElement>(null);
  const [selectedCategoryId, setSelectedCategoryId] = useState<number | null>(null);
  const [isNew, setIsNew] = useState(false);
  const [publishTarget, setPublishTarget] = useState<Category | null>(null);
  const [unpublishPreview, setUnpublishPreview] = useState<UnpublishPreviewResponse | null>(null);
  const [unpublishTarget, setUnpublishTarget] = useState<Category | null>(null);
  const [showSlugSetup, setShowSlugSetup] = useState(false);

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

  // Load categories when modal opens
  useEffect(() => {
    if (isOpen) {
      loadCategoriesForCollection(collectionId);
      /* eslint-disable react-hooks/set-state-in-effect -- Resetting selection state when modal opens */
      setSelectedCategoryId(null);
      setIsNew(false);
      /* eslint-enable react-hooks/set-state-in-effect */
    }
  }, [isOpen, collectionId, loadCategoriesForCollection]);

  const selectedCategory = selectedCategoryId
    ? categories.find(c => c.categoryId === selectedCategoryId) ?? null
    : null;

  const handleBackdropClick = (e: React.MouseEvent<HTMLDialogElement>) => {
    if (e.target === dialogRef.current) {
      onClose();
    }
  };

  const handleSelect = useCallback((categoryId: number) => {
    setSelectedCategoryId(categoryId);
    setIsNew(false);
  }, []);

  const handleAdd = useCallback(() => {
    setSelectedCategoryId(null);
    setIsNew(true);
  }, []);

  const handleCancel = useCallback(() => {
    setSelectedCategoryId(null);
    setIsNew(false);
  }, []);

  const handleSave = useCallback(async (updates: { name: string; description: string; parentCategoryId: number | null; itemTemplateIds: number[] }) => {
    try {
      if (isNew) {
        const newId = await addCategory({
          collectionId,
          name: updates.name,
          description: updates.description,
          parentCategoryId: updates.parentCategoryId,
          itemTemplateIds: updates.itemTemplateIds,
        });
        await loadCategoriesForCollection(collectionId);
        setSelectedCategoryId(newId);
        setIsNew(false);
      } else if (selectedCategoryId) {
        await updateCategory(selectedCategoryId, updates);
        await loadCategoriesForCollection(collectionId);
      }
    } catch (err) {
      console.error('Failed to save category:', err);
    }
  }, [isNew, selectedCategoryId, collectionId, addCategory, updateCategory, loadCategoriesForCollection]);

  const handleDelete = useCallback(async (categoryId: number) => {
    const cat = categories.find(c => c.categoryId === categoryId);
    if (!cat) return;

    if (!window.confirm(`Are you sure you want to delete "${cat.name}"? Items in this category will be moved to "Unassigned Items".`)) {
      return;
    }

    try {
      await deleteCategory(categoryId);
      setSelectedCategoryId(null);
      setIsNew(false);
      await loadCategoriesForCollection(collectionId);
    } catch (err) {
      console.error('Failed to delete category:', err);
    }
  }, [categories, deleteCategory, collectionId, loadCategoriesForCollection]);

  const handleReorder = useCallback(async (updates: { categoryId: number; sortOrder: number }[]) => {
    try {
      await reorderCategories(updates);
      await loadCategoriesForCollection(collectionId);
    } catch (err) {
      console.error('Failed to reorder categories:', err);
    }
  }, [reorderCategories, collectionId, loadCategoriesForCollection]);

  const handleReparent = useCallback(async (categoryId: number, newParentId: number | null) => {
    try {
      const cat = categories.find(c => c.categoryId === categoryId);
      if (!cat) return;

      await updateCategory(categoryId, {
        name: cat.name,
        description: cat.description,
        parentCategoryId: newParentId,
        itemTemplateIds: cat.itemTemplateIds,
      });

      // Compute new sort orders for the target sibling group
      const siblings = categories.filter(c => c.parentCategoryId === newParentId && c.categoryId !== categoryId && !c.isSystem);
      const sortUpdates = [
        ...siblings.map((s, i) => ({ categoryId: s.categoryId, sortOrder: i })),
        { categoryId, sortOrder: siblings.length },
      ];
      await reorderCategories(sortUpdates);
      await loadCategoriesForCollection(collectionId);
    } catch (err) {
      console.error('Failed to reparent category:', err);
    }
  }, [categories, updateCategory, reorderCategories, collectionId, loadCategoriesForCollection]);

  const handlePublish = useCallback((category: Category) => {
    setPublishTarget(category);
  }, []);

  const handlePublishConfirm = useCallback(async (includeChildren: boolean) => {
    if (!publishTarget) return;

    try {
      const result = await publishCategory(publishTarget.categoryId, includeChildren);
      setPublishTarget(null);

      if (result.requiresSlugSetup) {
        setShowSlugSetup(true);
        return;
      }

      showToast(buildPublishToastMessage(result), buildPublishToastDetails(result));
      await loadCategoriesForCollection(collectionId);
    } catch (err) {
      console.error('Failed to publish category:', err);
      setPublishTarget(null);
    }
  }, [publishTarget, publishCategory, collectionId, loadCategoriesForCollection, showToast]);

  const handlePublishCancel = useCallback(() => {
    setPublishTarget(null);
  }, []);

  const handleUnpublish = useCallback(async (category: Category) => {
    try {
      const preview = await getUnpublishCategoryPreview(category.categoryId);
      setUnpublishTarget(category);
      setUnpublishPreview(preview);
    } catch (err) {
      console.error('Failed to get unpublish preview:', err);
    }
  }, [getUnpublishCategoryPreview]);

  const handleUnpublishConfirm = useCallback(async () => {
    if (!unpublishTarget) return;

    try {
      const result = await unpublishCategory(unpublishTarget.categoryId);
      showToast(buildUnpublishToastMessage(result));
      setUnpublishTarget(null);
      setUnpublishPreview(null);
      await loadCategoriesForCollection(collectionId);
    } catch (err) {
      console.error('Failed to unpublish category:', err);
      setUnpublishTarget(null);
      setUnpublishPreview(null);
    }
  }, [unpublishTarget, unpublishCategory, collectionId, loadCategoriesForCollection, showToast]);

  const handleUnpublishCancel = useCallback(() => {
    setUnpublishTarget(null);
    setUnpublishPreview(null);
  }, []);

  const handleSlugConfirm = useCallback(async () => {
    setShowSlugSetup(false);
    await loadCategoriesForCollection(collectionId);
  }, [collectionId, loadCategoriesForCollection]);

  const handleSlugCancel = useCallback(() => {
    setShowSlugSetup(false);
  }, []);

  return (
    <dialog ref={dialogRef} className="modal-dialog modal-dialog--wide" onClick={handleBackdropClick}>
      <div className="modal modal--wide">
        <div className="modal__header">
          <h2 className="modal__title categoryManager__title">Category Manager</h2>
          <button
            type="button"
            className="modal__close"
            onClick={onClose}
            aria-label="Close"
          >
            &times;
          </button>
        </div>
        <div className="categoryManager">
          <div className="categoryManager__tree">
            <CategoryManagerTree
              categories={categories}
              selectedCategoryId={selectedCategoryId}
              onSelect={handleSelect}
              onAdd={handleAdd}
              onReorder={handleReorder}
              onReparent={handleReparent}
            />
          </div>
          <div className="categoryManager__form">
            <CategoryManagerForm
              category={selectedCategory}
              categories={categories}
              collectionId={collectionId}
              isNew={isNew}
              onSave={handleSave}
              onDelete={handleDelete}
              onPublish={handlePublish}
              onUnpublish={handleUnpublish}
              onCancel={handleCancel}
            />
          </div>
        </div>
      </div>

      {publishTarget && (
        <PublishConfirmModal
          entityType="category"
          entityName={publishTarget.name}
          itemCount={0}
          onConfirm={handlePublishConfirm}
          onCancel={handlePublishCancel}
        />
      )}

      {unpublishPreview && unpublishTarget && (
        <UnpublishConfirmModal
          entityType="category"
          entityName={unpublishTarget.name}
          affectedPublicItems={unpublishPreview.affectedPublicItems}
          affectedPublicCategories={unpublishPreview.affectedPublicCategories}
          onConfirm={handleUnpublishConfirm}
          onCancel={handleUnpublishCancel}
        />
      )}

      {showSlugSetup && (
        <SlugSetupModal
          onConfirm={handleSlugConfirm}
          onCancel={handleSlugCancel}
        />
      )}
    </dialog>
  );
}

export default CategoryManagerModal;
