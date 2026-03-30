import React, { useState, useEffect, useRef, useCallback } from 'react';
import type { Category } from '../../utils/types';
import { useData } from '../../contexts/useData';
import { usePublish } from '../../contexts/usePublish';
import { useDialog } from '../../utils/useDialog';
import CategoryManagerTree from './CategoryManagerTree';
import CategoryManagerForm from './CategoryManagerForm';
import QuickCreatePopover from './QuickCreatePopover';
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
  } = useData();
  const { requestPublish, requestUnpublish } = usePublish();

  const [dialogRef] = useDialog(isOpen, onClose);
  const formRef = useRef<{ submit: () => void } | null>(null);
  const [selectedCategoryId, setSelectedCategoryId] = useState<number | null>(null);
  const [isNew, setIsNew] = useState(false);
  const [formHasChanges, setFormHasChanges] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [showCancelConfirm, setShowCancelConfirm] = useState(false);
  const [view, setView] = useState<'tree' | 'form'>('tree');
  const [showQuickCreate, setShowQuickCreate] = useState(false);
  const [initialName, setInitialName] = useState('');

  // Load categories when modal opens and reset state
  useEffect(() => {
    if (isOpen) {
      loadCategoriesForCollection(collectionId);
      /* eslint-disable react-hooks/set-state-in-effect -- Resetting selection state when modal opens */
      setSelectedCategoryId(null);
      setIsNew(false);
      setFormHasChanges(false);
      setView('tree');
      setShowQuickCreate(false);
      setInitialName('');
      /* eslint-enable react-hooks/set-state-in-effect */
    }
  }, [isOpen, collectionId, loadCategoriesForCollection]);

  const selectedCategory = selectedCategoryId
    ? categories.find(c => c.categoryId === selectedCategoryId) ?? null
    : null;

  // Pending navigation target for discard confirmation
  const [pendingNavigation, setPendingNavigation] = useState<{ type: 'close' } | null>(null);

  const handleCloseAttempt = useCallback(() => {
    if (view === 'tree') {
      onClose();
    } else if (formHasChanges) {
      setPendingNavigation({ type: 'close' });
      setShowCancelConfirm(true);
    } else {
      setView('tree');
      setSelectedCategoryId(null);
    }
  }, [view, formHasChanges, onClose]);

  const handleBackdropClick = useCallback((e: React.MouseEvent<HTMLDialogElement>) => {
    if (e.target === dialogRef.current) {
      handleCloseAttempt();
    }
  }, [handleCloseAttempt]);

  const handleEditCategory = useCallback((categoryId: number) => {
    setSelectedCategoryId(categoryId);
    setIsNew(false);
    setInitialName('');
    setView('form');
  }, []);

  const handleAdd = useCallback(() => {
    setShowQuickCreate(true);
  }, []);

  const handleQuickCreateSave = useCallback(async (name: string) => {
    setShowQuickCreate(false);
    try {
      const newId = await addCategory({
        collectionId, name, description: '', parentCategoryId: null, itemTemplateIds: [],
      });
      const rootSiblings = categories.filter(c => c.parentCategoryId === null && !c.isSystem);
      const sortUpdates = [
        { categoryId: newId, sortOrder: 0 },
        ...rootSiblings.map((s, i) => ({ categoryId: s.categoryId, sortOrder: i + 1 })),
      ];
      await reorderCategories(sortUpdates);
      await loadCategoriesForCollection(collectionId);
    } catch (err) {
      console.error('Failed to create category:', err);
    }
  }, [collectionId, categories, addCategory, reorderCategories, loadCategoriesForCollection]);

  const handleQuickCreateMoreDetails = useCallback((name: string) => {
    setShowQuickCreate(false);
    setInitialName(name);
    setSelectedCategoryId(null);
    setIsNew(true);
    setView('form');
  }, []);

  const handleQuickCreateCancel = useCallback(() => {
    setShowQuickCreate(false);
  }, []);

  const handleBack = useCallback(() => {
    if (formHasChanges) {
      setPendingNavigation({ type: 'close' });
      setShowCancelConfirm(true);
    } else {
      setView('tree');
      setSelectedCategoryId(null);
    }
  }, [formHasChanges]);

  const handleCancelClick = useCallback(() => {
    if (formHasChanges) {
      setPendingNavigation(null);
      setShowCancelConfirm(true);
    }
  }, [formHasChanges]);

  const handleSaveClick = useCallback(() => {
    formRef.current?.submit();
  }, []);

  const handleDiscardConfirm = useCallback(() => {
    setShowCancelConfirm(false);
    setFormHasChanges(false);
    const nav = pendingNavigation;
    setPendingNavigation(null);
    if (nav?.type === 'close') {
      setView('tree');
      setSelectedCategoryId(null);
    }
  }, [pendingNavigation]);

  const handleSave = useCallback(async (updates: { name: string; description: string; parentCategoryId: number | null; itemTemplateIds: number[] }) => {
    try {
      if (isNew) {
        await addCategory({
          collectionId,
          name: updates.name,
          description: updates.description,
          parentCategoryId: updates.parentCategoryId,
          itemTemplateIds: updates.itemTemplateIds,
        });
        await loadCategoriesForCollection(collectionId);
        setView('tree');
        setSelectedCategoryId(null);
        setIsNew(false);
      } else if (selectedCategoryId) {
        await updateCategory(selectedCategoryId, updates);
        await loadCategoriesForCollection(collectionId);
        setView('tree');
        setSelectedCategoryId(null);
        setIsNew(false);
      }
    } catch (err) {
      console.error('Failed to save category:', err);
    }
  }, [isNew, selectedCategoryId, collectionId, addCategory, updateCategory, loadCategoriesForCollection]);

  const handleDeleteClick = useCallback(() => {
    if (selectedCategoryId && selectedCategory && !selectedCategory.isSystem) {
      setShowDeleteConfirm(true);
    }
  }, [selectedCategoryId, selectedCategory]);

  const handleDeleteConfirm = useCallback(async () => {
    if (!selectedCategoryId) return;
    const deletedId = selectedCategoryId;
    setShowDeleteConfirm(false);
    try {
      await deleteCategory(deletedId);
      await loadCategoriesForCollection(collectionId);
      setView('tree');
      setSelectedCategoryId(null);
      setIsNew(false);
      setFormHasChanges(false);
    } catch (err) {
      console.error('Failed to delete category:', err);
    }
  }, [selectedCategoryId, deleteCategory, collectionId, loadCategoriesForCollection]);

  const handleReorder = useCallback(async (updates: { categoryId: number; sortOrder: number }[]) => {
    try {
      await reorderCategories(updates);
      await loadCategoriesForCollection(collectionId);
    } catch (err) {
      console.error('Failed to reorder categories:', err);
    }
  }, [reorderCategories, collectionId, loadCategoriesForCollection]);

  const handleReparent = useCallback(async (categoryId: number, newParentId: number | null, insertAtCategoryId?: number, insertAfter?: boolean) => {
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
      const siblings = categories
        .filter(c => c.parentCategoryId === newParentId && c.categoryId !== categoryId && !c.isSystem)
        .sort((a, b) => a.sortOrder - b.sortOrder);

      let sortUpdates: { categoryId: number; sortOrder: number }[];

      if (insertAtCategoryId != null) {
        // Insert at a specific position relative to a sibling
        const targetIndex = siblings.findIndex(c => c.categoryId === insertAtCategoryId);
        if (targetIndex !== -1) {
          const insertIndex = insertAfter ? targetIndex + 1 : targetIndex;
          const reordered = [...siblings];
          reordered.splice(insertIndex, 0, cat);
          sortUpdates = reordered.map((c, i) => ({ categoryId: c.categoryId, sortOrder: i }));
        } else {
          // Target not found — append to end
          sortUpdates = [
            ...siblings.map((s, i) => ({ categoryId: s.categoryId, sortOrder: i })),
            { categoryId, sortOrder: siblings.length },
          ];
        }
      } else {
        // No position specified — append to end
        sortUpdates = [
          ...siblings.map((s, i) => ({ categoryId: s.categoryId, sortOrder: i })),
          { categoryId, sortOrder: siblings.length },
        ];
      }

      await reorderCategories(sortUpdates);
      await loadCategoriesForCollection(collectionId);
    } catch (err) {
      console.error('Failed to reparent category:', err);
    }
  }, [categories, updateCategory, reorderCategories, collectionId, loadCategoriesForCollection]);

  const handlePublish = useCallback((category: Category) => {
    requestPublish([{ type: 'category', id: category.categoryId }]);
  }, [requestPublish]);

  const handleUnpublish = useCallback((category: Category) => {
    requestUnpublish([{ type: 'category', id: category.categoryId }]);
  }, [requestUnpublish]);

  return (
    <dialog ref={dialogRef} className="modal-dialog modal-dialog--wide" onClick={handleBackdropClick}>
      <div className="modal modal--wide">
        <div className="modal__header">
          <h2 className="modal__title categoryManager__title">Category Manager</h2>
          <button
            type="button"
            className="modal__close"
            onClick={handleCloseAttempt}
            aria-label="Close"
          >
            &times;
          </button>
        </div>
        <div className="categoryManager">
          <div className={`categoryManager__track${view === 'form' ? ' categoryManager__track--form' : ''}`}>
            <div className="categoryManager__tree">
              <CategoryManagerTree
                categories={categories}
                onEditCategory={handleEditCategory}
                onAdd={handleAdd}
                onReorder={handleReorder}
                onReparent={handleReparent}
                toolbarSlot={showQuickCreate ? (
                  <QuickCreatePopover
                    isVisible={showQuickCreate}
                    onSave={handleQuickCreateSave}
                    onMoreDetails={handleQuickCreateMoreDetails}
                    onCancel={handleQuickCreateCancel}
                  />
                ) : undefined}
              />
            </div>
            <div className="categoryManager__form">
              <CategoryManagerForm
                category={selectedCategory}
                categories={categories}
                collectionId={collectionId}
                isNew={isNew}
                initialName={initialName}
                onSave={handleSave}
                onBack={handleBack}
                onPublish={handlePublish}
                onUnpublish={handleUnpublish}
                onHasChanges={setFormHasChanges}
                formRef={formRef}
              />
            </div>
          </div>
        </div>
        <div className="categoryManager__footer">
          {view === 'form' ? (
            <>
              {selectedCategory && !isNew && !selectedCategory.isSystem ? (
                <button type="button" className="modal__button modal__button--danger" onClick={handleDeleteClick}>
                  Delete
                </button>
              ) : (
                <div />
              )}
              <div className="categoryManager__footer-right">
                <button type="button" className="modal__button modal__button--secondary" onClick={handleCancelClick} disabled={!isNew && !formHasChanges}>
                  Cancel
                </button>
                <button type="button" className="modal__button modal__button--primary" onClick={handleSaveClick}>
                  {isNew ? 'Create' : 'Save Changes'}
                </button>
              </div>
            </>
          ) : (
            <>
              <div />
              <div className="categoryManager__footer-right">
                <button type="button" className="modal__button modal__button--secondary" onClick={onClose}>
                  Close
                </button>
              </div>
            </>
          )}
        </div>
      </div>

      {showDeleteConfirm && selectedCategory && (
        <div className="modal-overlay">
          <div className="modal" style={{ maxWidth: '420px' }}>
            <div className="modal__header">
              <h2 className="modal__title categoryManager__title">Delete Category</h2>
            </div>
            <div className="modal__body">
              <p className="modal__info">
                Are you sure you want to delete &ldquo;{selectedCategory.name}&rdquo;? Items in this category will be moved to &ldquo;Unassigned Items&rdquo;.
              </p>
            </div>
            <div className="modal__footer">
              <button
                type="button"
                className="modal__button modal__button--secondary"
                onClick={() => setShowDeleteConfirm(false)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="modal__button modal__button--danger"
                onClick={handleDeleteConfirm}
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}

      {showCancelConfirm && (
        <div className="modal-overlay">
          <div className="modal" style={{ maxWidth: '420px' }}>
            <div className="modal__header">
              <h2 className="modal__title categoryManager__title">Discard Changes</h2>
            </div>
            <div className="modal__body">
              <p className="modal__info">
                You have unsaved changes. Are you sure you want to discard them?
              </p>
            </div>
            <div className="modal__footer">
              <button
                type="button"
                className="modal__button modal__button--secondary"
                onClick={() => setShowCancelConfirm(false)}
              >
                Keep Editing
              </button>
              <button
                type="button"
                className="modal__button modal__button--danger"
                onClick={handleDiscardConfirm}
              >
                Discard
              </button>
            </div>
          </div>
        </div>
      )}
    </dialog>
  );
}

export default CategoryManagerModal;
