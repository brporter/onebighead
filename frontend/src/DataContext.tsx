import { createContext, useContext, useState, useCallback, useEffect, useRef, type ReactNode } from 'react';
import type { Category, Item, Collection, Tenant } from './types';
import { collections as initialCollections, tenants as initialTenants } from './data';

interface CategoryItemsCache {
  items: Item[];
  etag: string | null;
}

export interface DataContextValue {
  // Data
  categories: Category[];
  categoriesLoading: boolean;
  categoriesError: string | null;
  items: Item[];
  itemsLoading: boolean;
  itemsError: string | null;
  collections: Collection[];
  tenants: Tenant[];
  // Item operations
  addItem: (item: Item) => Promise<number>;
  updateItem: (id: number, updates: Partial<Item>) => Promise<void>;
  deleteItem: (id: number) => Promise<void>;
  loadItemsForCategory: (categoryId: number) => Promise<void>;
  // Category operations
  addCategory: (category: Omit<Category, 'categoryId' | 'isSystem'>) => Promise<number>;
  updateCategory: (categoryId: number, updates: Partial<Category>) => Promise<void>;
  deleteCategory: (categoryId: number) => Promise<void>;
  refreshCategories: () => Promise<void>;
  // Collection operations
  addCollection: (collection: Omit<Collection, 'collectionId'>) => void;
  updateCollection: (collectionId: number, updates: Partial<Collection>) => void;
  deleteCollection: (collectionId: number) => void;
  // Tenant operations
  addTenant: (tenant: Omit<Tenant, 'tenantId'>) => void;
  updateTenant: (tenantId: number, updates: Partial<Tenant>) => void;
  deleteTenant: (tenantId: number) => void;
}

const defaultContextValue: DataContextValue = {
  categories: [],
  categoriesLoading: false,
  categoriesError: null,
  items: [],
  itemsLoading: false,
  itemsError: null,
  collections: [],
  tenants: [],
  addItem: async () => 0,
  updateItem: async () => {},
  deleteItem: async () => {},
  loadItemsForCategory: async () => {},
  addCategory: async () => 0,
  updateCategory: async () => {},
  deleteCategory: async () => {},
  refreshCategories: async () => {},
  addCollection: () => {},
  updateCollection: () => {},
  deleteCollection: () => {},
  addTenant: () => {},
  updateTenant: () => {},
  deleteTenant: () => {},
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
  const [categories, setCategories] = useState<Category[]>([]);
  const [categoriesLoading, setCategoriesLoading] = useState(true);
  const [categoriesError, setCategoriesError] = useState<string | null>(null);
  const [items, setItems] = useState<Item[]>([]);
  const [itemsLoading, setItemsLoading] = useState(false);
  const [itemsError, setItemsError] = useState<string | null>(null);
  const [collections, setCollections] = useState<Collection[]>([...initialCollections]);
  const [tenants, setTenants] = useState<Tenant[]>([...initialTenants]);
  const [currentCategoryId, setCurrentCategoryId] = useState<number | null>(null);
  
  // Cache for items by category ID, storing items and their ETag
  const itemsCacheRef = useRef<Map<number, CategoryItemsCache>>(new Map());

  const fetchCategories = useCallback(async () => {
    try {
      setCategoriesLoading(true);
      setCategoriesError(null);
      const response = await fetch('/api/categories');
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

  useEffect(() => {
    fetchCategories();
  }, [fetchCategories]);

  const loadItemsForCategory = useCallback(async (categoryId: number) => {
    setCurrentCategoryId(categoryId);
    const cache = itemsCacheRef.current.get(categoryId);
    
    // If we have cached items, show them immediately while we validate
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
        // Not modified - cache is still valid
        setItemsLoading(false);
        return;
      }
      
      if (!response.ok) {
        throw new Error(`Failed to fetch items: ${response.statusText}`);
      }
      
      const data: Item[] = await response.json();
      const etag = response.headers.get('ETag');
      
      // Update cache
      itemsCacheRef.current.set(categoryId, { items: data, etag });
      
      // Only update state if this is still the current category
      if (categoryId === currentCategoryId || !cache) {
        setItems(data);
      }
    } catch (error) {
      setItemsError(error instanceof Error ? error.message : 'Failed to fetch items');
    } finally {
      setItemsLoading(false);
    }
  }, [currentCategoryId]);

  // Item CRUD operations
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
    
    // Invalidate cache for the item's category
    if (created.categoryId != null) {
      itemsCacheRef.current.delete(created.categoryId);
      // Also invalidate parent categories since they include descendants
      for (const [cachedCategoryId] of itemsCacheRef.current) {
        itemsCacheRef.current.delete(cachedCategoryId);
      }
    }
    
    setItems((prev) => [...prev, created]);
    return created.id!;
  }, []);

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
    
    // Invalidate all caches since category might have changed
    itemsCacheRef.current.clear();
    
    setItems((prev) =>
      prev.map((item) => (item.id === id ? result : item))
    );
  }, [items]);

  const deleteItem = useCallback(async (id: number): Promise<void> => {
    const response = await fetch(`/api/items/${id}`, {
      method: 'DELETE',
    });
    if (!response.ok) {
      throw new Error(`Failed to delete item: ${response.statusText}`);
    }
    
    // Invalidate all caches
    itemsCacheRef.current.clear();
    
    setItems((prev) => prev.filter((item) => item.id !== id));
  }, []);

  // Category CRUD operations
  const addCategory = useCallback(async (category: Omit<Category, 'categoryId' | 'isSystem'>): Promise<number> => {
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

  const updateCategory = useCallback(async (categoryId: number, updates: Partial<Category>): Promise<void> => {
    const currentCategory = categories.find((c) => c.categoryId === categoryId);
    if (!currentCategory) return;
    
    const updatedCategory = { ...currentCategory, ...updates };
    const response = await fetch(`/api/categories/${categoryId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updatedCategory),
    });
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(errorText || `Failed to update category: ${response.statusText}`);
    }
    const result: Category = await response.json();
    setCategories((prev) =>
      prev.map((cat) => (cat.categoryId === categoryId ? result : cat))
    );
  }, [categories]);

  const deleteCategory = useCallback(async (categoryId: number): Promise<void> => {
    const response = await fetch(`/api/categories/${categoryId}`, {
      method: 'DELETE',
    });
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(errorText || `Failed to delete category: ${response.statusText}`);
    }
    setCategories((prev) => prev.filter((cat) => cat.categoryId !== categoryId));
    // Clear items cache since items may have been reassigned
    itemsCacheRef.current.clear();
  }, []);

  // Collection CRUD operations
  const addCollection = useCallback((collection: Omit<Collection, 'collectionId'>) => {
    setCollections((prev) => {
      const newId = prev.length ? Math.max(...prev.map((c) => c.collectionId)) + 1 : 1;
      return [...prev, { ...collection, collectionId: newId }];
    });
  }, []);

  const updateCollection = useCallback((collectionId: number, updates: Partial<Collection>) => {
    setCollections((prev) =>
      prev.map((col) => (col.collectionId === collectionId ? { ...col, ...updates } : col))
    );
  }, []);

  const deleteCollection = useCallback((collectionId: number) => {
    setCollections((prev) => prev.filter((col) => col.collectionId !== collectionId));
  }, []);

  // Tenant CRUD operations
  const addTenant = useCallback((tenant: Omit<Tenant, 'tenantId'>) => {
    setTenants((prev) => {
      const newId = prev.length ? Math.max(...prev.map((t) => t.tenantId)) + 1 : 1;
      return [...prev, { ...tenant, tenantId: newId }];
    });
  }, []);

  const updateTenant = useCallback((tenantId: number, updates: Partial<Tenant>) => {
    setTenants((prev) =>
      prev.map((t) => (t.tenantId === tenantId ? { ...t, ...updates } : t))
    );
  }, []);

  const deleteTenant = useCallback((tenantId: number) => {
    setTenants((prev) => prev.filter((t) => t.tenantId !== tenantId));
  }, []);

  const value: DataContextValue = {
    // Data
    categories,
    categoriesLoading,
    categoriesError,
    items,
    itemsLoading,
    itemsError,
    collections,
    tenants,
    // Item operations
    addItem,
    updateItem,
    deleteItem,
    loadItemsForCategory,
    // Category operations
    addCategory,
    updateCategory,
    deleteCategory,
    refreshCategories: fetchCategories,
    // Collection operations
    addCollection,
    updateCollection,
    deleteCollection,
    // Tenant operations
    addTenant,
    updateTenant,
    deleteTenant,
  };

  return <DataContext.Provider value={value}>{children}</DataContext.Provider>;
}

export default DataContext;

