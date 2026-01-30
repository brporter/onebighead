import { createContext, useContext, useState, useCallback, useRef, useEffect, type ReactNode } from 'react';
import type { Category, Item, Collection, ItemTemplate, CreateItemTemplateRequest, UpdateItemTemplateRequest, CollectionTheme, SetupCollectionRequest } from '../utils/types';
import { collectionsApi, categoriesApi, itemsApi, imagesApi, templatesApi, suggestionsApi, themesApi, ApiError } from '../api';

interface CategoryItemsCache {
  items: Item[];
  etag: string | null;
}

interface PropertySuggestionsCache {
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
  addCollection: (name: string, description?: string, heroImageUrl?: string, isPublic?: boolean) => Promise<Collection>;
  setupCollection: (request: SetupCollectionRequest) => Promise<Collection>;
  updateCollection: (collectionId: number, updates: { name: string; description?: string; heroImageUrl?: string; isPublic?: boolean }) => Promise<void>;
  deleteCollection: (collectionId: number) => Promise<void>;
  
  // Collection themes
  themes: CollectionTheme[];
  themesLoading: boolean;
  themesError: string | null;
  loadThemes: () => Promise<void>;
  
  // Categories (scoped to current collection)
  categories: Category[];
  categoriesLoading: boolean;
  categoriesError: string | null;
  loadCategoriesForCollection: (collectionId: number) => Promise<void>;
  addCategory: (category: { collectionId: number; name: string; description?: string; parentCategoryId?: number | null; isPublicOverride?: boolean | null; itemTemplateIds?: number[] }) => Promise<number>;
  updateCategory: (categoryId: number, updates: { name: string; description?: string; parentCategoryId?: number | null; isPublicOverride?: boolean | null; itemTemplateIds?: number[] }) => Promise<void>;
  deleteCategory: (categoryId: number) => Promise<void>;
  getCategoryTemplates: (categoryId: number) => Promise<number[]>;
  
  // Items (scoped to current collection/category)
  items: Item[];
  itemsLoading: boolean;
  itemsError: string | null;
  loadItemsForCategory: (categoryId: number) => Promise<void>;
  loadItemById: (itemId: number) => Promise<Item | null>;
  addItem: (item: Item) => Promise<number>;
  updateItem: (id: number, updates: Partial<Item>) => Promise<void>;
  deleteItem: (id: number) => Promise<void>;

  // Image upload
  uploadImage: (file: File) => Promise<{ key: string; url: string }>;

  // Property suggestions (scoped to current collection)
  propertyCategorySuggestions: string[];
  propertyNameSuggestions: string[];
  loadPropertySuggestions: (collectionId: number) => Promise<void>;
  syncPropertySuggestions: (collectionId: number) => Promise<void>;
  addLocalCategorySuggestion: (category: string) => void;
  addLocalNameSuggestion: (name: string) => void;

  // Item templates
  itemTemplates: ItemTemplate[];
  itemTemplatesLoading: boolean;
  itemTemplatesError: string | null;
  loadItemTemplates: (filter?: 'shared' | 'personal') => Promise<void>;
  loadCollectionTemplates: (collectionId: number) => Promise<ItemTemplate[]>;
  createItemTemplate: (request: CreateItemTemplateRequest) => Promise<ItemTemplate>;
  updateItemTemplate: (id: number, request: UpdateItemTemplateRequest) => Promise<ItemTemplate>;
  deleteItemTemplate: (id: number) => Promise<void>;
  associateTemplateWithCollection: (collectionId: number, templateId: number) => Promise<void>;
  disassociateTemplateFromCollection: (collectionId: number, templateId: number) => Promise<void>;
}

const defaultContextValue: DataContextValue = {
  currentCollection: null,
  setCurrentCollection: () => {},
  collections: [],
  collectionsLoading: false,
  collectionsError: null,
  loadCollections: async () => {},
  addCollection: async () => ({ collectionId: 0, tenantId: 0, name: '', description: '', heroImageUrl: null, slug: '', isPublic: false }),
  setupCollection: async () => ({ collectionId: 0, tenantId: 0, name: '', description: '', heroImageUrl: null, slug: '', isPublic: false }),
  updateCollection: async () => {},
  deleteCollection: async () => {},
  themes: [],
  themesLoading: false,
  themesError: null,
  loadThemes: async () => {},
  categories: [],
  categoriesLoading: false,
  categoriesError: null,
  loadCategoriesForCollection: async () => {},
  addCategory: async () => 0,
  updateCategory: async () => {},
  deleteCategory: async () => {},
  getCategoryTemplates: async () => [],
  items: [],
  itemsLoading: false,
  itemsError: null,
  loadItemsForCategory: async () => {},
  loadItemById: async () => null,
  addItem: async () => 0,
  updateItem: async () => {},
  deleteItem: async () => {},
  uploadImage: async () => ({ key: '', url: '' }),
  propertyCategorySuggestions: [],
  propertyNameSuggestions: [],
  loadPropertySuggestions: async () => {},
  syncPropertySuggestions: async () => {},
  addLocalCategorySuggestion: () => {},
  addLocalNameSuggestion: () => {},
  itemTemplates: [],
  itemTemplatesLoading: false,
  itemTemplatesError: null,
  loadItemTemplates: async () => {},
  loadCollectionTemplates: async () => [],
  createItemTemplate: async () => ({ itemTemplateId: 0, name: '', description: '', isSystem: false, properties: [], createdAt: '', updatedAt: '' }),
  updateItemTemplate: async () => ({ itemTemplateId: 0, name: '', description: '', isSystem: false, properties: [], createdAt: '', updatedAt: '' }),
  deleteItemTemplate: async () => {},
  associateTemplateWithCollection: async () => {},
  disassociateTemplateFromCollection: async () => {},
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
  
  const [themes, setThemes] = useState<CollectionTheme[]>([]);
  const [themesLoading, setThemesLoading] = useState(false);
  const [themesError, setThemesError] = useState<string | null>(null);
  
  const [categories, setCategories] = useState<Category[]>([]);
  const [categoriesLoading, setCategoriesLoading] = useState(false);
  const [categoriesError, setCategoriesError] = useState<string | null>(null);
  
  const [items, setItems] = useState<Item[]>([]);
  const [itemsLoading, setItemsLoading] = useState(false);
  const [itemsError, setItemsError] = useState<string | null>(null);
  const [currentCategoryId, setCurrentCategoryId] = useState<number | null>(null);
  
  const itemsCacheRef = useRef<Map<number, CategoryItemsCache>>(new Map());
  const propertySuggestionsCacheRef = useRef<Map<number, PropertySuggestionsCache>>(new Map());
  const pendingSyncRef = useRef<number | null>(null);
  
  // Property suggestions state (fetched from backend API)
  const [propertyCategorySuggestions, setPropertyCategorySuggestions] = useState<string[]>([]);
  const [propertyNameSuggestions, setPropertyNameSuggestions] = useState<string[]>([]);

  // Item templates state
  const [itemTemplates, setItemTemplates] = useState<ItemTemplate[]>([]);
  const [itemTemplatesLoading, setItemTemplatesLoading] = useState(false);
  const [itemTemplatesError, setItemTemplatesError] = useState<string | null>(null);

  // Load property suggestions from API with caching
  const loadPropertySuggestions = useCallback(async (collectionId: number) => {
    // Check cache first
    const cached = propertySuggestionsCacheRef.current.get(collectionId);
    if (cached) {
      setPropertyCategorySuggestions(cached.categories);
      setPropertyNameSuggestions(cached.names);
      return;
    }
    
    try {
      const data = await suggestionsApi.get(collectionId);
      const categories = data.categories.sort();
      const names = data.names.sort();
      propertySuggestionsCacheRef.current.set(collectionId, { categories, names });
      setPropertyCategorySuggestions(categories);
      setPropertyNameSuggestions(names);
    } catch (error) {
      console.error('Failed to load property suggestions:', error);
    }
  }, []);

  // Sync property suggestions with debouncing (recalculates based on current items)
  const syncPropertySuggestions = useCallback(async (collectionId: number) => {
    // Clear any pending sync
    if (pendingSyncRef.current !== null) {
      clearTimeout(pendingSyncRef.current);
    }
    
    // Debounce: wait 2 seconds before syncing
    pendingSyncRef.current = window.setTimeout(async () => {
      try {
        const data = await suggestionsApi.sync(collectionId);
        const categories = data.categories.sort();
        const names = data.names.sort();
        propertySuggestionsCacheRef.current.set(collectionId, { categories, names });
        setPropertyCategorySuggestions(categories);
        setPropertyNameSuggestions(names);
      } catch (error) {
        console.error('Failed to sync property suggestions:', error);
      }
      pendingSyncRef.current = null;
    }, 2000);
  }, []);

  // Cleanup pending sync timeout on unmount to prevent memory leaks
  useEffect(() => {
    return () => {
      if (pendingSyncRef.current !== null) {
        clearTimeout(pendingSyncRef.current);
      }
    };
  }, []);

  // Add a local category suggestion (not persisted until item is saved)
  const addLocalCategorySuggestion = useCallback((category: string) => {
    if (category.trim()) {
      setPropertyCategorySuggestions((prev) => {
        if (prev.includes(category)) return prev;
        return [...prev, category].sort();
      });
    }
  }, []);

  // Add a local name suggestion (not persisted until item is saved)
  const addLocalNameSuggestion = useCallback((name: string) => {
    if (name.trim()) {
      setPropertyNameSuggestions((prev) => {
        if (prev.includes(name)) return prev;
        return [...prev, name].sort();
      });
    }
  }, []);

  // Collection operations
  const loadCollections = useCallback(async () => {
    try {
      setCollectionsLoading(true);
      setCollectionsError(null);
      const data = await collectionsApi.getAll();
      setCollections(data);
    } catch (error) {
      setCollectionsError(error instanceof Error ? error.message : 'Failed to fetch collections');
    } finally {
      setCollectionsLoading(false);
    }
  }, []);

  const addCollection = useCallback(async (name: string, description?: string, heroImageUrl?: string, isPublic?: boolean): Promise<Collection> => {
    const created = await collectionsApi.create({ name, description, heroImageUrl, isPublic });
    setCollections((prev) => [...prev, created]);
    return created;
  }, []);

  const setupCollection = useCallback(async (request: SetupCollectionRequest): Promise<Collection> => {
    const created = await collectionsApi.setup(request);
    setCollections((prev) => [...prev, created]);
    return created;
  }, []);

  const updateCollection = useCallback(async (collectionId: number, updates: { name: string; description?: string; heroImageUrl?: string; isPublic?: boolean }): Promise<void> => {
    const result = await collectionsApi.update(collectionId, updates);
    setCollections((prev) =>
      prev.map((col) => (col.collectionId === collectionId ? result : col))
    );
    if (currentCollection?.collectionId === collectionId) {
      setCurrentCollection(result);
    }
  }, [currentCollection]);

  const deleteCollection = useCallback(async (collectionId: number): Promise<void> => {
    await collectionsApi.delete(collectionId);
    setCollections((prev) => prev.filter((col) => col.collectionId !== collectionId));
  }, []);

  // Theme operations
  const loadThemes = useCallback(async () => {
    try {
      setThemesLoading(true);
      setThemesError(null);
      const data = await themesApi.getAll();
      setThemes(data);
    } catch (error) {
      setThemesError(error instanceof Error ? error.message : 'Failed to fetch themes');
    } finally {
      setThemesLoading(false);
    }
  }, []);

  // Category operations
  const loadCategoriesForCollection = useCallback(async (collectionId: number) => {
    try {
      setCategoriesLoading(true);
      setCategoriesError(null);
      const data = await categoriesApi.getAll(collectionId);
      setCategories(data);
    } catch (error) {
      setCategoriesError(error instanceof Error ? error.message : 'Failed to fetch categories');
    } finally {
      setCategoriesLoading(false);
    }
  }, []);

  const addCategory = useCallback(async (category: { collectionId: number; name: string; description?: string; parentCategoryId?: number | null; isPublicOverride?: boolean | null; itemTemplateIds?: number[] }): Promise<number> => {
    const created = await categoriesApi.create(category);
    setCategories((prev) => [...prev, created]);
    return created.categoryId;
  }, []);

  const updateCategory = useCallback(async (categoryId: number, updates: { name: string; description?: string; parentCategoryId?: number | null; isPublicOverride?: boolean | null; itemTemplateIds?: number[] }): Promise<void> => {
    const result = await categoriesApi.update(categoryId, updates);
    setCategories((prev) =>
      prev.map((cat) => (cat.categoryId === categoryId ? result : cat))
    );
  }, []);

  const deleteCategory = useCallback(async (categoryId: number): Promise<void> => {
    await categoriesApi.delete(categoryId);
    setCategories((prev) => prev.filter((cat) => cat.categoryId !== categoryId));
    itemsCacheRef.current.clear();
  }, []);

  const getCategoryTemplates = useCallback(async (categoryId: number): Promise<number[]> => {
    return await categoriesApi.getTemplates(categoryId);
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
      
      const result = await itemsApi.getAll({
        categoryId,
        includeDescendants: true,
        etag: cache?.etag ?? undefined,
      });
      
      if (result.notModified) {
        setItemsLoading(false);
        return;
      }
      
      itemsCacheRef.current.set(categoryId, { items: result.items, etag: result.etag });
      
      if (categoryId === currentCategoryId || !cache) {
        setItems(result.items);
      }
    } catch (error) {
      setItemsError(error instanceof Error ? error.message : 'Failed to fetch items');
    } finally {
      setItemsLoading(false);
    }
  }, [currentCategoryId]);

  // Load a single item by ID (for deep linking)
  const loadItemById = useCallback(async (itemId: number): Promise<Item | null> => {
    try {
      const item = await itemsApi.getById(itemId);
      // Add item to items array if not already present
      setItems((prev) => {
        const exists = prev.some((i) => i.id === item.id);
        return exists ? prev : [...prev, item];
      });
      return item;
    } catch (error) {
      if (error instanceof ApiError) {
        console.error(`Failed to load item ${itemId}: ${error.message} (status: ${error.status})`);
      } else {
        console.error('Failed to load item by ID:', error);
      }
      return null;
    }
  }, []);

  const addItem = useCallback(async (item: Item): Promise<number> => {
    const created = await itemsApi.create(item);
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
    const result = await itemsApi.update(id, updatedItem);
    itemsCacheRef.current.clear();
    setItems((prev) =>
      prev.map((item) => (item.id === id ? result : item))
    );
    // Sync property suggestions to reflect property changes
    syncPropertySuggestions(result.collectionId);
  }, [items, syncPropertySuggestions]);

  const deleteItem = useCallback(async (id: number): Promise<void> => {
    const itemToDelete = items.find((i) => i.id === id);
    await itemsApi.delete(id);
    itemsCacheRef.current.clear();
    setItems((prev) => prev.filter((item) => item.id !== id));
    // Sync property suggestions to remove unused ones
    if (itemToDelete) {
      syncPropertySuggestions(itemToDelete.collectionId);
    }
  }, [items, syncPropertySuggestions]);

  const uploadImage = useCallback(async (file: File): Promise<{ key: string; url: string }> => {
    return await imagesApi.upload(file);
  }, []);

  // Item template operations
  const loadItemTemplates = useCallback(async (filter?: 'shared' | 'personal') => {
    try {
      setItemTemplatesLoading(true);
      setItemTemplatesError(null);
      const data = await templatesApi.getAll(filter);
      setItemTemplates(data);
    } catch (error) {
      setItemTemplatesError(error instanceof Error ? error.message : 'Failed to fetch item templates');
    } finally {
      setItemTemplatesLoading(false);
    }
  }, []);

  const loadCollectionTemplates = useCallback(async (collectionId: number): Promise<ItemTemplate[]> => {
    return await templatesApi.getForCollection(collectionId);
  }, []);

  const createItemTemplate = useCallback(async (request: CreateItemTemplateRequest): Promise<ItemTemplate> => {
    const created = await templatesApi.create(request);
    setItemTemplates((prev) => [...prev, created].sort((a, b) => a.name.localeCompare(b.name)));
    return created;
  }, []);

  const updateItemTemplate = useCallback(async (id: number, request: UpdateItemTemplateRequest): Promise<ItemTemplate> => {
    const updated = await templatesApi.update(id, request);
    setItemTemplates((prev) =>
      prev.map((t) => (t.itemTemplateId === id ? updated : t)).sort((a, b) => a.name.localeCompare(b.name))
    );
    return updated;
  }, []);

  const deleteItemTemplate = useCallback(async (id: number): Promise<void> => {
    await templatesApi.delete(id);
    setItemTemplates((prev) => prev.filter((t) => t.itemTemplateId !== id));
  }, []);

  const associateTemplateWithCollection = useCallback(async (collectionId: number, templateId: number): Promise<void> => {
    await templatesApi.associateWithCollection(collectionId, templateId);
  }, []);

  const disassociateTemplateFromCollection = useCallback(async (collectionId: number, templateId: number): Promise<void> => {
    await templatesApi.disassociateFromCollection(collectionId, templateId);
  }, []);

  const value: DataContextValue = {
    currentCollection,
    setCurrentCollection,
    collections,
    collectionsLoading,
    collectionsError,
    loadCollections,
    addCollection,
    setupCollection,
    updateCollection,
    deleteCollection,
    themes,
    themesLoading,
    themesError,
    loadThemes,
    categories,
    categoriesLoading,
    categoriesError,
    loadCategoriesForCollection,
    addCategory,
    updateCategory,
    deleteCategory,
    getCategoryTemplates,
    items,
    itemsLoading,
    itemsError,
    loadItemsForCategory,
    loadItemById,
    addItem,
    updateItem,
    deleteItem,
    uploadImage,
    propertyCategorySuggestions,
    propertyNameSuggestions,
    loadPropertySuggestions,
    syncPropertySuggestions,
    addLocalCategorySuggestion,
    addLocalNameSuggestion,
    itemTemplates,
    itemTemplatesLoading,
    itemTemplatesError,
    loadItemTemplates,
    loadCollectionTemplates,
    createItemTemplate,
    updateItemTemplate,
    deleteItemTemplate,
    associateTemplateWithCollection,
    disassociateTemplateFromCollection,
  };

  return <DataContext.Provider value={value}>{children}</DataContext.Provider>;
}

export default DataContext;
