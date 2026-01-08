import { createContext, useContext, useState, useCallback, useRef, type ReactNode } from 'react';
import type { Category, Item, Collection } from './types';

interface CategoryItemsCache {
  items: Item[];
  etag: string | null;
}

interface PropertySuggestionsResponse {
  categories: string[];
  names: string[];
}

export interface DataContextValue {
  // Current collection
  currentCollection: Collection | null;
  setCurrentCollection: (collection: Collection | null) => void;
  
  // Collections
  collections: Collection[];
  collectionsLoading: boolean;
  collectionsError: string | null;
  loadCollections: () => Promise<void>;
  addCollection: (name: string, description?: string, heroImageUrl?: string) => Promise<Collection>;
  updateCollection: (collectionId: number, updates: { name: string; description?: string; heroImageUrl?: string }) => Promise<void>;
  deleteCollection: (collectionId: number) => Promise<void>;
  
  // Categories (scoped to current collection)
  categories: Category[];
  categoriesLoading: boolean;
  categoriesError: string | null;
  loadCategoriesForCollection: (collectionId: number) => Promise<void>;
  addCategory: (category: { collectionId: number; name: string; description?: string; parentCategoryId?: number | null }) => Promise<number>;
  updateCategory: (categoryId: number, updates: { name: string; description?: string; parentCategoryId?: number | null }) => Promise<void>;
  deleteCategory: (categoryId: number) => Promise<void>;
  
  // Items (scoped to current collection/category)
  items: Item[];
  itemsLoading: boolean;
  itemsError: string | null;
  loadItemsForCategory: (categoryId: number) => Promise<void>;
  addItem: (item: Item) => Promise<number>;
  updateItem: (id: number, updates: Partial<Item>) => Promise<void>;
  deleteItem: (id: number) => Promise<void>;

  // Property suggestions (scoped to current collection)
  propertyCategorySuggestions: string[];
  propertyNameSuggestions: string[];
  loadPropertySuggestions: (collectionId: number) => Promise<void>;
  syncPropertySuggestions: (collectionId: number) => Promise<void>;
}

const defaultContextValue: DataContextValue = {
  currentCollection: null,
  setCurrentCollection: () => {},
  collections: [],
  collectionsLoading: false,
  collectionsError: null,
  loadCollections: async () => {},
  addCollection: async () => ({ collectionId: 0, tenantId: 0, name: '', description: '', heroImageUrl: null, slug: '' }),
  updateCollection: async () => {},
  deleteCollection: async () => {},
  categories: [],
  categoriesLoading: false,
  categoriesError: null,
  loadCategoriesForCollection: async () => {},
  addCategory: async () => 0,
  updateCategory: async () => {},
  deleteCategory: async () => {},
  items: [],
  itemsLoading: false,
  itemsError: null,
  loadItemsForCategory: async () => {},
  addItem: async () => 0,
  updateItem: async () => {},
  deleteItem: async () => {},
  propertyCategorySuggestions: [],
  propertyNameSuggestions: [],
  loadPropertySuggestions: async () => {},
  syncPropertySuggestions: async () => {},
};

const DataContext = createContext<DataContextValue>(defaultContextValue);

// eslint-disable-next-line react-refresh/only-export-components
export function useData(): DataContextValue {
  return useContext(DataContext);
}

interface DataProviderProps {
  children: ReactNode;
}

export function DataProvider({ children }: DataProviderProps) {
  const [currentCollection, setCurrentCollection] = useState<Collection | null>(null);
  
  const [collections, setCollections] = useState<Collection[]>([]);
  const [collectionsLoading, setCollectionsLoading] = useState(false);
  const [collectionsError, setCollectionsError] = useState<string | null>(null);
  
  const [categories, setCategories] = useState<Category[]>([]);
  const [categoriesLoading, setCategoriesLoading] = useState(false);
  const [categoriesError, setCategoriesError] = useState<string | null>(null);
  
  const [items, setItems] = useState<Item[]>([]);
  const [itemsLoading, setItemsLoading] = useState(false);
  const [itemsError, setItemsError] = useState<string | null>(null);
  const [currentCategoryId, setCurrentCategoryId] = useState<number | null>(null);
  
  const itemsCacheRef = useRef<Map<number, CategoryItemsCache>>(new Map());
  
  // Property suggestions state (fetched from backend API)
  const [propertyCategorySuggestions, setPropertyCategorySuggestions] = useState<string[]>([]);
  const [propertyNameSuggestions, setPropertyNameSuggestions] = useState<string[]>([]);

  // Load property suggestions from API
  const loadPropertySuggestions = useCallback(async (collectionId: number) => {
    try {
      const response = await fetch(`/api/collections/${collectionId}/property-suggestions`);
      if (!response.ok) {
        console.error('Failed to load property suggestions:', response.statusText);
        return;
      }
      const data: PropertySuggestionsResponse = await response.json();
      setPropertyCategorySuggestions(data.categories.sort());
      setPropertyNameSuggestions(data.names.sort());
    } catch (error) {
      console.error('Failed to load property suggestions:', error);
    }
  }, []);

  // Sync property suggestions (recalculates based on current items)
  const syncPropertySuggestions = useCallback(async (collectionId: number) => {
    try {
      const response = await fetch(`/api/collections/${collectionId}/property-suggestions/sync`, {
        method: 'POST',
      });
      if (!response.ok) {
        console.error('Failed to sync property suggestions:', response.statusText);
        return;
      }
      const data: PropertySuggestionsResponse = await response.json();
      setPropertyCategorySuggestions(data.categories.sort());
      setPropertyNameSuggestions(data.names.sort());
    } catch (error) {
      console.error('Failed to sync property suggestions:', error);
    }
  }, []);

  // Collection operations
  const loadCollections = useCallback(async () => {
    try {
      setCollectionsLoading(true);
      setCollectionsError(null);
      const response = await fetch('/api/collections');
      if (!response.ok) {
        throw new Error(`Failed to fetch collections: ${response.statusText}`);
      }
      const data: Collection[] = await response.json();
      setCollections(data);
    } catch (error) {
      setCollectionsError(error instanceof Error ? error.message : 'Failed to fetch collections');
    } finally {
      setCollectionsLoading(false);
    }
  }, []);

  const addCollection = useCallback(async (name: string, description?: string, heroImageUrl?: string): Promise<Collection> => {
    const response = await fetch('/api/collections', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, description, heroImageUrl }),
    });
    if (!response.ok) {
      throw new Error(`Failed to create collection: ${response.statusText}`);
    }
    const created: Collection = await response.json();
    setCollections((prev) => [...prev, created]);
    return created;
  }, []);

  const updateCollection = useCallback(async (collectionId: number, updates: { name: string; description?: string; heroImageUrl?: string }): Promise<void> => {
    const response = await fetch(`/api/collections/${collectionId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates),
    });
    if (!response.ok) {
      throw new Error(`Failed to update collection: ${response.statusText}`);
    }
    const result: Collection = await response.json();
    setCollections((prev) =>
      prev.map((col) => (col.collectionId === collectionId ? result : col))
    );
    if (currentCollection?.collectionId === collectionId) {
      setCurrentCollection(result);
    }
  }, [currentCollection]);

  const deleteCollection = useCallback(async (collectionId: number): Promise<void> => {
    const response = await fetch(`/api/collections/${collectionId}`, {
      method: 'DELETE',
    });
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(errorText || `Failed to delete collection: ${response.statusText}`);
    }
    setCollections((prev) => prev.filter((col) => col.collectionId !== collectionId));
  }, []);

  // Category operations
  const loadCategoriesForCollection = useCallback(async (collectionId: number) => {
    try {
      setCategoriesLoading(true);
      setCategoriesError(null);
      const response = await fetch(`/api/categories?collectionId=${collectionId}`);
      if (!response.ok) {
        throw new Error(`Failed to fetch categories: ${response.statusText}`);
      }
      const data: Category[] = await response.json();
      setCategories(data);
    } catch (error) {
      setCategoriesError(error instanceof Error ? error.message : 'Failed to fetch categories');
    } finally {
      setCategoriesLoading(false);
    }
  }, []);

  const addCategory = useCallback(async (category: { collectionId: number; name: string; description?: string; parentCategoryId?: number | null }): Promise<number> => {
    const response = await fetch('/api/categories', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(category),
    });
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(errorText || `Failed to create category: ${response.statusText}`);
    }
    const created: Category = await response.json();
    setCategories((prev) => [...prev, created]);
    return created.categoryId;
  }, []);

  const updateCategory = useCallback(async (categoryId: number, updates: { name: string; description?: string; parentCategoryId?: number | null }): Promise<void> => {
    const response = await fetch(`/api/categories/${categoryId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates),
    });
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(errorText || `Failed to update category: ${response.statusText}`);
    }
    const result: Category = await response.json();
    setCategories((prev) =>
      prev.map((cat) => (cat.categoryId === categoryId ? result : cat))
    );
  }, []);

  const deleteCategory = useCallback(async (categoryId: number): Promise<void> => {
    const response = await fetch(`/api/categories/${categoryId}`, {
      method: 'DELETE',
    });
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(errorText || `Failed to delete category: ${response.statusText}`);
    }
    setCategories((prev) => prev.filter((cat) => cat.categoryId !== categoryId));
    itemsCacheRef.current.clear();
  }, []);

  // Item operations
  const loadItemsForCategory = useCallback(async (categoryId: number) => {
    setCurrentCategoryId(categoryId);
    const cache = itemsCacheRef.current.get(categoryId);
    
    if (cache) {
      setItems(cache.items);
    }
    
    try {
      setItemsLoading(true);
      setItemsError(null);
      
      const headers: HeadersInit = {};
      if (cache?.etag) {
        headers['If-None-Match'] = cache.etag;
      }
      
      const response = await fetch(
        `/api/items?categoryId=${categoryId}&includeDescendants=true`,
        { headers }
      );
      
      if (response.status === 304) {
        setItemsLoading(false);
        return;
      }
      
      if (!response.ok) {
        throw new Error(`Failed to fetch items: ${response.statusText}`);
      }
      
      const data: Item[] = await response.json();
      const etag = response.headers.get('ETag');
      
      itemsCacheRef.current.set(categoryId, { items: data, etag });
      
      if (categoryId === currentCategoryId || !cache) {
        setItems(data);
      }
    } catch (error) {
      setItemsError(error instanceof Error ? error.message : 'Failed to fetch items');
    } finally {
      setItemsLoading(false);
    }
  }, [currentCategoryId]);

  const addItem = useCallback(async (item: Item): Promise<number> => {
    const response = await fetch('/api/items', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(item),
    });
    if (!response.ok) {
      throw new Error(`Failed to create item: ${response.statusText}`);
    }
    const created: Item = await response.json();
    itemsCacheRef.current.clear();
    setItems((prev) => [...prev, created]);
    // Sync property suggestions to include new property names/categories
    syncPropertySuggestions(created.collectionId);
    return created.id!;
  }, [syncPropertySuggestions]);

  const updateItem = useCallback(async (id: number, updates: Partial<Item>): Promise<void> => {
    const currentItem = items.find((i) => i.id === id);
    if (!currentItem) return;
    
    const updatedItem = { ...currentItem, ...updates };
    const response = await fetch(`/api/items/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updatedItem),
    });
    if (!response.ok) {
      throw new Error(`Failed to update item: ${response.statusText}`);
    }
    const result: Item = await response.json();
    itemsCacheRef.current.clear();
    setItems((prev) =>
      prev.map((item) => (item.id === id ? result : item))
    );
    // Sync property suggestions to reflect property changes
    syncPropertySuggestions(result.collectionId);
  }, [items, syncPropertySuggestions]);

  const deleteItem = useCallback(async (id: number): Promise<void> => {
    const itemToDelete = items.find((i) => i.id === id);
    const response = await fetch(`/api/items/${id}`, {
      method: 'DELETE',
    });
    if (!response.ok) {
      throw new Error(`Failed to delete item: ${response.statusText}`);
    }
    itemsCacheRef.current.clear();
    setItems((prev) => prev.filter((item) => item.id !== id));
    // Sync property suggestions to remove unused ones
    if (itemToDelete) {
      syncPropertySuggestions(itemToDelete.collectionId);
    }
  }, [items, syncPropertySuggestions]);

  const value: DataContextValue = {
    currentCollection,
    setCurrentCollection,
    collections,
    collectionsLoading,
    collectionsError,
    loadCollections,
    addCollection,
    updateCollection,
    deleteCollection,
    categories,
    categoriesLoading,
    categoriesError,
    loadCategoriesForCollection,
    addCategory,
    updateCategory,
    deleteCategory,
    items,
    itemsLoading,
    itemsError,
    loadItemsForCategory,
    addItem,
    updateItem,
    deleteItem,
    propertyCategorySuggestions,
    propertyNameSuggestions,
    loadPropertySuggestions,
    syncPropertySuggestions,
  };

  return <DataContext.Provider value={value}>{children}</DataContext.Provider>;
}

export default DataContext;
