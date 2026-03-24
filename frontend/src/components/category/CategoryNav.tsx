import React, { useMemo, useState } from 'react';
import type { Category } from '../../utils/types';
import type { UnpublishPreviewResponse } from '../../utils/types';
import { useData } from '../../contexts/useData';
import { useToast } from '../../contexts/useToast';
import { buildPublishToastMessage, buildPublishToastDetails, buildUnpublishToastMessage } from '../../utils/publishToastUtils';
import { getAccentColor } from '../../utils/accentColors';
import { buildDrillPath, getVisibleCategories, getBreadcrumb } from '../../utils/categoryNavUtils';
import CategoryEditorModal from './CategoryEditorModal';
import { PublishButton, PublicBadge, PublishConfirmModal, UnpublishConfirmModal, SlugSetupModal } from '../common';
import './CategoryNav.css';

interface CategoryNavProps {
  categories: Category[];
  selectedCategoryId: number | null;
  onSelect: (categoryId: number | null) => void;
  onCollapse?: () => void;
}

function CategoryNav({ categories, selectedCategoryId, onSelect, onCollapse }: CategoryNavProps) {
  const {
    categoriesLoading,
    categoriesError,
    items,
    currentCollection,
    loadCategoriesForCollection,
    loadItemsForCategory,
    publishCategory,
    unpublishCategory,
    getUnpublishCategoryPreview,
  } = useData();
  const { showToast } = useToast();

  const [modalOpen, setModalOpen] = useState(false);
  const [editingCategory, setEditingCategory] = useState<Category | null>(null);
  const [publishTarget, setPublishTarget] = useState<Category | null>(null);
  const [unpublishTarget, setUnpublishTarget] = useState<Category | null>(null);
  const [unpublishPreview, setUnpublishPreview] = useState<UnpublishPreviewResponse | null>(null);
  const [showSlugSetup, setShowSlugSetup] = useState(false);

  // Filter out system categories that have no items
  const visibleCategories = useMemo(() => {
    const itemCategoryIds = new Set(
      items.map((item) => item.categoryId).filter((id): id is number => id !== null)
    );
    return categories.filter((cat) => {
      if (!cat.isSystem) return true;
      return itemCategoryIds.has(cat.categoryId);
    });
  }, [categories, items]);

  // Build drill path; if selected category is a leaf, slice off last element to stay at parent level
  const drillPath = useMemo(() => {
    const fullPath = buildDrillPath(visibleCategories, selectedCategoryId);
    if (fullPath.length === 0) return fullPath;

    const lastId = fullPath[fullPath.length - 1];
    const children = visibleCategories.filter(c => c.parentCategoryId === lastId);
    if (children.length === 0 && fullPath.length > 1) {
      // Leaf category: stay at parent level
      return fullPath.slice(0, -1);
    }
    return fullPath;
  }, [visibleCategories, selectedCategoryId]);

  const displayedCategories = useMemo(
    () => getVisibleCategories(visibleCategories, drillPath),
    [visibleCategories, drillPath]
  );

  const breadcrumb = useMemo(
    () => getBreadcrumb(visibleCategories, drillPath),
    [visibleCategories, drillPath]
  );

  const isDrilled = drillPath.length > 0;

  // Current drilled-into category (last in path)
  const currentDrilledCategory = useMemo(() => {
    if (!isDrilled) return null;
    const id = drillPath[drillPath.length - 1];
    return visibleCategories.find(c => c.categoryId === id) ?? null;
  }, [isDrilled, drillPath, visibleCategories]);

  // Compute root color index: walk up to root ancestor for consistent coloring
  const rootColorIndex = useMemo(() => {
    if (!isDrilled) return 0;
    const rootId = drillPath[0];
    const roots = visibleCategories.filter(c => c.parentCategoryId === null);
    return roots.findIndex(c => c.categoryId === rootId);
  }, [isDrilled, drillPath, visibleCategories]);

  // Precompute child counts and root color indices for O(1) lookups
  const childCountMap = useMemo(() => {
    const map = new Map<number, number>();
    visibleCategories.forEach((cat) => {
      if (cat.parentCategoryId != null) {
        map.set(cat.parentCategoryId, (map.get(cat.parentCategoryId) ?? 0) + 1);
      }
    });
    return map;
  }, [visibleCategories]);

  const rootIndexMap = useMemo(() => {
    const byId = new Map(visibleCategories.map(c => [c.categoryId, c]));
    const roots = visibleCategories.filter(c => c.parentCategoryId === null);
    const map = new Map<number, number>();
    visibleCategories.forEach((cat) => {
      let current = cat;
      while (current.parentCategoryId !== null) {
        const parent = byId.get(current.parentCategoryId);
        if (!parent) break;
        current = parent;
      }
      map.set(cat.categoryId, roots.findIndex(c => c.categoryId === current.categoryId));
    });
    return map;
  }, [visibleCategories]);

  function handleEdit(category: Category) {
    setEditingCategory(category);
    setModalOpen(true);
  }

  function handleAddNew() {
    setEditingCategory(null);
    setModalOpen(true);
  }

  function handleModalClose() {
    setModalOpen(false);
    setEditingCategory(null);
  }

  async function handleModalSaved() {
    if (currentCollection) {
      await loadCategoriesForCollection(currentCollection.collectionId);
      if (selectedCategoryId) {
        await loadItemsForCategory(selectedCategoryId);
      }
    }
  }

  function handlePublishClick(category: Category) {
    setPublishTarget(category);
  }

  async function handlePublishConfirm(includeChildren: boolean) {
    if (!publishTarget) return;
    const result = await publishCategory(publishTarget.categoryId, includeChildren);
    setPublishTarget(null);
    if (result.requiresSlugSetup) {
      setShowSlugSetup(true);
      return;
    }
    showToast(buildPublishToastMessage(result), buildPublishToastDetails(result));
    if (currentCollection) {
      await loadCategoriesForCollection(currentCollection.collectionId);
    }
  }

  function handlePublishCancel() {
    setPublishTarget(null);
  }

  async function handleUnpublishClick(category: Category) {
    const preview = await getUnpublishCategoryPreview(category.categoryId);
    setUnpublishPreview(preview);
    setUnpublishTarget(category);
  }

  async function handleUnpublishConfirm() {
    if (!unpublishTarget) return;
    const result = await unpublishCategory(unpublishTarget.categoryId);
    showToast(buildUnpublishToastMessage(result));
    setUnpublishTarget(null);
    setUnpublishPreview(null);
    if (currentCollection) {
      await loadCategoriesForCollection(currentCollection.collectionId);
    }
  }

  function handleUnpublishCancel() {
    setUnpublishTarget(null);
    setUnpublishPreview(null);
  }

  async function handleSlugConfirm() {
    setShowSlugSetup(false);
    if (currentCollection) {
      await loadCategoriesForCollection(currentCollection.collectionId);
    }
  }

  function handleBack() {
    if (drillPath.length <= 1) {
      onSelect(null);
    } else {
      // Go up to the parent of the current drilled level
      const parentId = drillPath[drillPath.length - 2];
      onSelect(parentId);
    }
  }

  if (categoriesError) {
    return (
      <aside className="categoryNav">
        <h2 className="categoryNav__headerTitle">Categories</h2>
        <p className="categoryNav__error" role="alert">Error loading categories: {categoriesError}</p>
      </aside>
    );
  }

  if (categoriesLoading) {
    return (
      <aside className="categoryNav">
        <h2 className="categoryNav__headerTitle">Categories</h2>
        <p className="categoryNav__loading">Loading categories...</p>
      </aside>
    );
  }

  return (
    <aside className="categoryNav">
      <div className="categoryNav__header">
        <h2 className="categoryNav__headerTitle">Categories</h2>
        <div className="categoryNav__headerActions">
          <button
            type="button"
            className="categoryNav__addBtn"
            onClick={handleAddNew}
            aria-label="Add category"
          >
            +
          </button>
          {onCollapse && (
            <button
              type="button"
              className="categoryNav__collapseBtn"
              onClick={onCollapse}
              aria-label="Collapse categories"
            >
              &laquo;
            </button>
          )}
        </div>
      </div>

      {isDrilled && (
        <nav className="categoryNav__breadcrumb" aria-label="Category breadcrumb">
          {breadcrumb.map((segment, idx) => {
            const isLast = idx === breadcrumb.length - 1;
            if (isLast) {
              return (
                <span key={segment.id ?? 'all'} className="categoryNav__breadcrumb-current">
                  {segment.name}
                </span>
              );
            }
            return (
              <React.Fragment key={segment.id ?? 'all'}>
                <button
                  type="button"
                  className="categoryNav__breadcrumb-link"
                  onClick={() => onSelect(segment.id)}
                  aria-label={`Navigate to ${segment.name}`}
                >
                  {segment.name}
                </button>
                <span className="categoryNav__breadcrumb-sep" aria-hidden="true">&rsaquo;</span>
              </React.Fragment>
            );
          })}
        </nav>
      )}

      <div className="categoryNav__list">
        {isDrilled && (
          <button
            type="button"
            className="categoryNav__back"
            onClick={handleBack}
            aria-label="Go back"
          >
            &larr; Back
          </button>
        )}

        {isDrilled && currentDrilledCategory && (
          <div
            className={`categoryNav__row${selectedCategoryId === currentDrilledCategory.categoryId ? ' categoryNav__row--active' : ''}`}
            onClick={() => onSelect(currentDrilledCategory.categoryId)}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); e.stopPropagation(); onSelect(currentDrilledCategory.categoryId); } }}
          >
            <span
              className="categoryNav__dot"
              style={{ backgroundColor: getAccentColor(rootColorIndex >= 0 ? rootColorIndex : 0).start }}
              aria-hidden="true"
            />
            <div className="categoryNav__rowContent">
              <span className="categoryNav__name">All {currentDrilledCategory.name}</span>
            </div>
          </div>
        )}

        {displayedCategories.map((cat) => {
          const colorIdx = isDrilled ? (rootColorIndex >= 0 ? rootColorIndex : 0) : (rootIndexMap.get(cat.categoryId) ?? 0);
          const childCount = childCountMap.get(cat.categoryId) ?? 0;
          const hasChildren = childCount > 0;
          const isActive = cat.categoryId === selectedCategoryId;

          return (
            <div
              key={cat.categoryId}
              className={`categoryNav__row${isActive ? ' categoryNav__row--active' : ''}`}
              onClick={() => onSelect(cat.categoryId)}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); e.stopPropagation(); onSelect(cat.categoryId); } }}
            >
              <span
                className="categoryNav__dot"
                style={{ backgroundColor: getAccentColor(colorIdx >= 0 ? colorIdx : 0).start }}
                aria-hidden="true"
              />
              <div className="categoryNav__rowContent">
                <span className="categoryNav__name">{cat.name}</span>
                {childCount > 0 && (
                  <span className="categoryNav__count">({childCount})</span>
                )}
              </div>

              {!cat.isSystem && cat.effectiveIsPublic ? (
                <PublicBadge
                  effectiveIsPublic={cat.effectiveIsPublic}
                  onUnpublish={() => handleUnpublishClick(cat)}
                  className="categoryNav__badge"
                />
              ) : !cat.isSystem ? (
                <PublishButton
                  onPublish={() => handlePublishClick(cat)}
                  className="categoryNav__publish-btn"
                />
              ) : null}

              {!cat.isSystem && (
                <button
                  type="button"
                  className="categoryNav__edit"
                  aria-label={`Edit ${cat.name}`}
                  onClick={(e) => {
                    e.stopPropagation();
                    handleEdit(cat);
                  }}
                >
                  &#9998;
                </button>
              )}

              {hasChildren && (
                <span className="categoryNav__chevron" aria-hidden="true">&rsaquo;</span>
              )}
            </div>
          );
        })}

        {displayedCategories.length === 0 && !isDrilled && (
          <p className="categoryNav__empty">No categories yet</p>
        )}
      </div>

      <CategoryEditorModal
        category={editingCategory}
        isOpen={modalOpen}
        onClose={handleModalClose}
        onSaved={handleModalSaved}
      />

      {publishTarget && (
        <PublishConfirmModal
          entityType="category"
          entityName={publishTarget.name}
          itemCount={items.filter(i => i.categoryId === publishTarget.categoryId).length}
          onConfirm={handlePublishConfirm}
          onCancel={handlePublishCancel}
        />
      )}

      {unpublishTarget && unpublishPreview && (
        <UnpublishConfirmModal
          entityType="category"
          entityName={unpublishTarget.name}
          affectedPublicItems={unpublishPreview.affectedPublicItems}
          onConfirm={handleUnpublishConfirm}
          onCancel={handleUnpublishCancel}
        />
      )}

      {showSlugSetup && (
        <SlugSetupModal
          onConfirm={handleSlugConfirm}
          onCancel={() => setShowSlugSetup(false)}
        />
      )}
    </aside>
  );
}

export { CategoryNav };
export default CategoryNav;
