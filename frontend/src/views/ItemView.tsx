import { useEffect, useState, useMemo, useRef } from 'react';
import { useParams, useNavigate, useSearchParams, Link } from 'react-router-dom';
import { useData } from '../contexts/useData';
import ItemDetail from '../components/item/ItemDetail';
import ItemEditor from '../components/item/ItemEditor';
import { BackNav, Loading, BulkUpdateModal, type ScopeOption } from '../components/common';
import CategoryTree from '../components/category/CategoryTree';
import TemplateSelector from '../components/template/TemplateSelector';
import { bulkUpdatesApi } from '../api/bulkUpdates';
import { itemsApi } from '../api/items';
import { createEmptyItem } from '../utils/itemUtils';
import type { Item, ItemProperty } from '../utils/types';

function ItemView() {
  const { collectionId, itemId } = useParams<{ collectionId: string; itemId: string }>();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  
  const {
    collections,
    collectionsLoading,
    loadCollections,
    currentCollection,
    setCurrentCollection,
    categories,
    loadCategoriesForCollection,
    items,
    loadItemsForCategory,
    loadItemById,
    addItem,
    updateItem,
    deleteItem,
    loadPropertySuggestions,
    invalidateItemCache,
  } = useData();

  const [isEditing, setIsEditing] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [deepLinkedItem, setDeepLinkedItem] = useState<Item | null>(null);
  const [showTemplateSelector, setShowTemplateSelector] = useState(false);
  const [selectedTemplateProperties, setSelectedTemplateProperties] = useState<ItemProperty[] | null>(null);
  const [selectedTemplateKey, setSelectedTemplateKey] = useState<string | null>(null);

  // Bulk update state
  const [showBulkUpdateModal, setShowBulkUpdateModal] = useState(false);
  const [bulkUpdateScopeOptions, setBulkUpdateScopeOptions] = useState<ScopeOption[]>([]);
  const [bulkUpdateOldProps, setBulkUpdateOldProps] = useState<{ category: string; name: string }[]>([]);
  const [bulkUpdateNewProps, setBulkUpdateNewProps] = useState<{ category: string; name: string }[]>([]);
  const originalItemPropsRef = useRef<ItemProperty[]>([]);

  const collectionIdNum = collectionId ? parseInt(collectionId, 10) : null;
  const isNewItem = itemId === 'new';
  const itemIdNum = !isNewItem && itemId ? parseInt(itemId, 10) : null;
  const categoryIdFromUrl = searchParams.get('categoryId');
  const categoryIdNum = categoryIdFromUrl ? parseInt(categoryIdFromUrl, 10) : null;

  // Deep linking: Load collection data if needed
  useEffect(() => {
    if (!collectionsLoading && collections.length === 0) {
      loadCollections();
    }
  }, [collectionsLoading, collections.length, loadCollections]);

  // Set current collection once collections are loaded
  useEffect(() => {
    if (collectionIdNum && collections.length > 0 && currentCollection?.collectionId !== collectionIdNum) {
      const collection = collections.find(c => c.collectionId === collectionIdNum);
      if (collection) {
        setCurrentCollection(collection);
        loadCategoriesForCollection(collectionIdNum);
        loadPropertySuggestions(collectionIdNum);
      } else {
        navigate('/collections', { replace: true });
      }
    }
  }, [collectionIdNum, collections, currentCollection, setCurrentCollection, loadCategoriesForCollection, loadPropertySuggestions, navigate]);

  // Load items for the category if we have one (for deep linking)
  useEffect(() => {
    if (categoryIdNum && currentCollection) {
      loadItemsForCategory(categoryIdNum);
    }
  }, [categoryIdNum, currentCollection, loadItemsForCategory]);

  // For existing items, fetch the item directly if we don't have it (deep linking)
  useEffect(() => {
    async function fetchItemForDeepLink() {
      if (itemIdNum && currentCollection && categories.length > 0) {
        // Check if we already have the item
        const existingItem = items.find(i => i.id === itemIdNum);
        if (existingItem) {
          setDeepLinkedItem(null); // Clear deep linked item, use from items array
          if (existingItem.categoryId) {
            loadItemsForCategory(existingItem.categoryId);
          }
          setIsLoading(false);
        } else {
          // Fetch the item directly for deep linking
          const item = await loadItemById(itemIdNum);
          if (item) {
            setDeepLinkedItem(item);
            if (item.categoryId) {
              loadItemsForCategory(item.categoryId);
            }
          }
          setIsLoading(false);
        }
      } else if (!itemIdNum) {
        setIsLoading(false);
      }
    }
    fetchItemForDeepLink();
  }, [itemIdNum, currentCollection, categories.length, items, loadItemsForCategory, loadItemById]);

  // Show template selector for new items - computed from state, no effect needed
  // This is a derived state that should show selector when conditions are met
  const shouldShowTemplateSelector = isNewItem && currentCollection && selectedTemplateProperties === null && !showTemplateSelector;
  if (shouldShowTemplateSelector) {
    setShowTemplateSelector(true);
  }

  const selectedItem = useMemo(() => {
    if (itemIdNum == null) return null;
    // First check items array, then fall back to deep linked item
    return items.find((item) => item.id === itemIdNum) ?? deepLinkedItem;
  }, [items, itemIdNum, deepLinkedItem]);

  // Fire-and-forget view tracking (ref guards against StrictMode double-invoke)
  const lastViewedItemId = useRef<number | null>(null);
  useEffect(() => {
    if (selectedItem?.id && selectedItem.id !== lastViewedItemId.current) {
      lastViewedItemId.current = selectedItem.id;
      itemsApi.recordView(selectedItem.id).catch(() => {});
    }
  }, [selectedItem?.id]);

  const newItemTemplate = useMemo(() => {
    if (!isNewItem || categoryIdNum == null || !currentCollection) return null;
    const emptyItem = createEmptyItem(categoryIdNum, currentCollection.collectionId, currentCollection.workspaceId, selectedTemplateKey);
    // Apply selected template properties if available
    if (selectedTemplateProperties && selectedTemplateProperties.length > 0) {
      emptyItem.properties = selectedTemplateProperties;
    }
    return emptyItem;
  }, [isNewItem, categoryIdNum, currentCollection, selectedTemplateProperties, selectedTemplateKey]);

  const detailItem = isNewItem ? newItemTemplate : selectedItem;

  function handleBackToItems() {
    const catId = detailItem?.categoryId ?? categoryIdNum;
    if (catId) {
      navigate(`/collections/${collectionIdNum}/categories/${catId}`);
    } else {
      navigate(`/collections/${collectionIdNum}`);
    }
  }

  function handleTemplateSelected(selection: { properties: ItemProperty[]; templateKey: string | null }) {
    setSelectedTemplateProperties(selection.properties);
    setSelectedTemplateKey(selection.templateKey);
    setShowTemplateSelector(false);
  }

  function handleTemplateSelectorClose() {
    // If user closes without selecting, go back to items list
    handleBackToItems();
  }

  function handleEditItem() {
    // Capture original properties for bulk update comparison
    if (selectedItem) {
      originalItemPropsRef.current = [...selectedItem.properties];
    }
    setIsEditing(true);
  }

  function handleCancelEdit() {
    if (isNewItem) {
      handleBackToItems();
    } else {
      setIsEditing(false);
    }
  }

  async function handleSaveItem(itemData: Item) {
    if (isNewItem) {
      await addItem(itemData);
      handleBackToItems();
    } else if (itemIdNum != null) {
      await updateItem(itemIdNum, itemData);
      setIsEditing(false);

      // Check if properties changed - offer bulk update for siblings
      const oldProps = originalItemPropsRef.current;
      const newProps = itemData.properties;
      const propsChanged = oldProps.length !== newProps.length ||
        oldProps.some((op, i) => op.category !== newProps[i]?.category || op.name !== newProps[i]?.name);

      if (propsChanged && itemData.categoryId) {
        try {
          const scopeOptions: ScopeOption[] = [];

          const categoryPreview = await bulkUpdatesApi.preview({
            scope: 'category',
            categoryId: itemData.categoryId,
            excludeItemId: itemIdNum,
          });
          if (categoryPreview.affectedItemCount > 0) {
            const cat = categories.find(c => c.categoryId === itemData.categoryId);
            scopeOptions.push({
              scope: 'category',
              label: `in "${cat?.name ?? 'this category'}"`,
              count: categoryPreview.affectedItemCount,
              categoryId: itemData.categoryId,
            });
          }

          const collectionPreview = await bulkUpdatesApi.preview({
            scope: 'collection',
            collectionId: itemData.collectionId,
            excludeItemId: itemIdNum,
          });
          if (collectionPreview.affectedItemCount > 0) {
            scopeOptions.push({
              scope: 'collection',
              label: 'in this collection',
              count: collectionPreview.affectedItemCount,
              collectionId: itemData.collectionId,
            });
          }

          if (scopeOptions.length > 0) {
            setBulkUpdateOldProps(oldProps.map(p => ({ category: p.category, name: p.name })));
            setBulkUpdateNewProps(newProps.map(p => ({ category: p.category, name: p.name })));
            setBulkUpdateScopeOptions(scopeOptions);
            setShowBulkUpdateModal(true);
          }
        } catch {
          // Preview failed - skip bulk update offer
        }
      }
    }
  }

  function handleBulkUpdateClose() {
    setShowBulkUpdateModal(false);
  }

  function handleBulkUpdateComplete() {
    setShowBulkUpdateModal(false);
    // Invalidate item cache so next navigation shows updated data
    invalidateItemCache();
    if (detailItem?.categoryId) {
      loadItemsForCategory(detailItem.categoryId);
    }
  }

  async function handleDeleteItem(id: number) {
    await deleteItem(id);
    handleBackToItems();
  }

  function handleSelectCategory(catId: number) {
    navigate(`/collections/${collectionIdNum}/categories/${catId}`);
  }

  function handleBackToCollections() {
    navigate('/collections');
  }

  const showBackToCollections = collections.length > 1;

  if (isLoading || collectionsLoading) {
    return <Loading message="Loading..." />;
  }

  if (!currentCollection) {
    return <Loading message="Collection not found" />;
  }

  if (!isNewItem && !selectedItem) {
    return <Loading message="Item not found" />;
  }

  // For new items, show template selector first
  if (isNewItem && showTemplateSelector && collectionIdNum) {
    return (
      <TemplateSelector
        collectionId={collectionIdNum}
        categoryId={categoryIdNum}
        isOpen={true}
        onClose={handleTemplateSelectorClose}
        onSelect={handleTemplateSelected}
      />
    );
  }

  // For new items, wait until template is selected (or skipped)
  if (isNewItem && selectedTemplateProperties === null) {
    return <Loading message="Loading..." />;
  }

  return (
    <div className="app__layout">
      <nav className="app__sidebar" aria-label="Category navigation">
        <CategoryTree
          categories={categories}
          selectedCategoryId={detailItem?.categoryId ?? null}
          onSelect={handleSelectCategory}
        />
      </nav>
      <main className="app__content">
        <div className="collection-title-bar">
          {showBackToCollections && (
            <button className="collection-title-bar__back" onClick={handleBackToCollections}>
              ← All Collections
            </button>
          )}
          <Link to={`/collections/${collectionIdNum}`} className="collection-title-bar__title-link">
            <h1 className="collection-title-bar__title">{currentCollection.name}</h1>
          </Link>
        </div>
        <article className="app__detail">
          <BackNav label="Back to items" onClick={handleBackToItems} />
          {isEditing || isNewItem ? (
            <ItemEditor
              item={detailItem}
              categories={categories}
              collection={currentCollection}
              onSave={handleSaveItem}
              onCancel={handleCancelEdit}
              onDelete={isNewItem ? undefined : handleDeleteItem}
              initialProperties={isNewItem ? (selectedTemplateProperties ?? undefined) : undefined}
            />
          ) : (
            <ItemDetail
              item={detailItem}
              onEdit={handleEditItem}
              onClose={handleBackToItems}
            />
          )}
        </article>
        <BulkUpdateModal
          isOpen={showBulkUpdateModal}
          onClose={handleBulkUpdateClose}
          onComplete={handleBulkUpdateComplete}
          scopeOptions={bulkUpdateScopeOptions}
          oldProperties={bulkUpdateOldProps}
          newProperties={bulkUpdateNewProps}
          excludeItemId={itemIdNum ?? undefined}
        />
      </main>
    </div>
  );
}

export default ItemView;
