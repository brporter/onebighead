import { useEffect, useState, useMemo } from 'react';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import { useData } from '../DataContext';
import ItemDetail from '../ItemDetail';
import ItemEditor from '../ItemEditor';
import BackNav from '../BackNav';
import CategoryTree from '../CategoryTree';
import TemplateSelector from '../TemplateSelector';
import { createEmptyItem } from '../itemUtils';
import type { Item, ItemProperty } from '../types';

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
  } = useData();

  const [isEditing, setIsEditing] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [deepLinkedItem, setDeepLinkedItem] = useState<Item | null>(null);
  const [showTemplateSelector, setShowTemplateSelector] = useState(false);
  const [selectedTemplateProperties, setSelectedTemplateProperties] = useState<ItemProperty[] | null>(null);

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

  // Show template selector for new items
  useEffect(() => {
    if (isNewItem && currentCollection && selectedTemplateProperties === null) {
      setShowTemplateSelector(true);
    }
  }, [isNewItem, currentCollection, selectedTemplateProperties]);

  const selectedItem = useMemo(() => {
    if (itemIdNum == null) return null;
    // First check items array, then fall back to deep linked item
    return items.find((item) => item.id === itemIdNum) ?? deepLinkedItem;
  }, [items, itemIdNum, deepLinkedItem]);

  const newItemTemplate = useMemo(() => {
    if (!isNewItem || categoryIdNum == null || !currentCollection) return null;
    const emptyItem = createEmptyItem(categoryIdNum, currentCollection.collectionId, currentCollection.tenantId);
    // Apply selected template properties if available
    if (selectedTemplateProperties && selectedTemplateProperties.length > 0) {
      emptyItem.properties = selectedTemplateProperties;
    }
    return emptyItem;
  }, [isNewItem, categoryIdNum, currentCollection, selectedTemplateProperties]);

  const detailItem = isNewItem ? newItemTemplate : selectedItem;

  function handleBackToItems() {
    const catId = detailItem?.categoryId ?? categoryIdNum;
    if (catId) {
      navigate(`/collections/${collectionIdNum}/categories/${catId}`);
    } else {
      navigate(`/collections/${collectionIdNum}`);
    }
  }

  function handleTemplateSelected(properties: ItemProperty[]) {
    setSelectedTemplateProperties(properties);
    setShowTemplateSelector(false);
  }

  function handleTemplateSelectorClose() {
    // If user closes without selecting, go back to items list
    handleBackToItems();
  }

  function handleEditItem() {
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
    }
  }

  async function handleDeleteItem(id: number) {
    await deleteItem(id);
    handleBackToItems();
  }

  function handleSelectCategory(catId: number) {
    navigate(`/collections/${collectionIdNum}/categories/${catId}`);
  }

  if (isLoading || collectionsLoading) {
    return <div className="app__loading">Loading...</div>;
  }

  if (!currentCollection) {
    return <div className="app__loading">Collection not found</div>;
  }

  if (!isNewItem && !selectedItem) {
    return <div className="app__loading">Item not found</div>;
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
    return <div className="app__loading">Loading...</div>;
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
      </main>
    </div>
  );
}

export default ItemView;
