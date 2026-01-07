import { createContext, useContext, useState, useCallback, useEffect, type ReactNode } from 'react';
import type { Category, Item, Collection, Tenant } from './types';
import { collections as initialCollections, tenants as initialTenants } from './data';

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
  refreshItems: () => Promise<void>;
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
  refreshItems: async () => {},
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
  const [itemsLoading, setItemsLoading] = useState(true);
  const [itemsError, setItemsError] = useState<string | null>(null);
  const [collections, setCollections] = useState<Collection[]>([...initialCollections]);
  const [tenants, setTenants] = useState<Tenant[]>([...initialTenants]);

  const fetchItems = useCallback(async () => {
    try {
      setItemsLoading(true);
      setItemsError(null);
      const response = await fetch('/api/items');
      if (!response.ok) {
        throw new Error(`Failed to fetch items: ${response.statusText}`);
      }
      const data: Item[] = await response.json();
      setItems(data);
    } catch (error) {
      setItemsError(error instanceof Error ? error.message : 'Failed to fetch items');
    } finally {
      setItemsLoading(false);
    }
  }, []);

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
    fetchItems();
  }, [fetchCategories, fetchItems]);

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
    // Refresh items since they may have been reassigned to Unassigned Items
    await fetchItems();
  }, [fetchItems]);

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
    refreshItems: fetchItems,
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

