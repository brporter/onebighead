import { createContext, useContext, useState, useCallback, type ReactNode } from 'react';
import type { Category, Item, Collection, Tenant } from './types';
import { categories as initialCategories, items as initialItems, collections as initialCollections, tenants as initialTenants } from './data';

export interface DataContextValue {
  // Data
  categories: Category[];
  items: Item[];
  collections: Collection[];
  tenants: Tenant[];
  // Item operations
  addItem: (item: Item) => number;
  updateItem: (id: number, updates: Partial<Item>) => void;
  deleteItem: (id: number) => void;
  // Category operations
  addCategory: (category: Omit<Category, 'categoryId'>) => void;
  updateCategory: (categoryId: number, updates: Partial<Category>) => void;
  deleteCategory: (categoryId: number) => void;
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
  items: [],
  collections: [],
  tenants: [],
  addItem: () => 0,
  updateItem: () => {},
  deleteItem: () => {},
  addCategory: () => {},
  updateCategory: () => {},
  deleteCategory: () => {},
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
  const [categories, setCategories] = useState<Category[]>([...initialCategories]);
  const [items, setItems] = useState<Item[]>([...initialItems] as Item[]);
  const [collections, setCollections] = useState<Collection[]>([...initialCollections]);
  const [tenants, setTenants] = useState<Tenant[]>([...initialTenants]);

  // Item CRUD operations
  const addItem = useCallback((item: Item): number => {
    let newId = 0;
    setItems((prev) => {
      newId = prev.length ? Math.max(...prev.map((i) => i.id ?? 0)) + 1 : 1;
      return [...prev, { ...item, id: newId }];
    });
    return newId;
  }, []);

  const updateItem = useCallback((id: number, updates: Partial<Item>) => {
    setItems((prev) =>
      prev.map((item) => (item.id === id ? { ...item, ...updates } : item))
    );
  }, []);

  const deleteItem = useCallback((id: number) => {
    setItems((prev) => prev.filter((item) => item.id !== id));
  }, []);

  // Category CRUD operations
  const addCategory = useCallback((category: Omit<Category, 'categoryId'>) => {
    setCategories((prev) => {
      const newId = prev.length ? Math.max(...prev.map((c) => c.categoryId)) + 1 : 1;
      return [...prev, { ...category, categoryId: newId }];
    });
  }, []);

  const updateCategory = useCallback((categoryId: number, updates: Partial<Category>) => {
    setCategories((prev) =>
      prev.map((cat) => (cat.categoryId === categoryId ? { ...cat, ...updates } : cat))
    );
  }, []);

  const deleteCategory = useCallback((categoryId: number) => {
    setCategories((prev) => prev.filter((cat) => cat.categoryId !== categoryId));
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
    items,
    collections,
    tenants,
    // Item operations
    addItem,
    updateItem,
    deleteItem,
    // Category operations
    addCategory,
    updateCategory,
    deleteCategory,
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

