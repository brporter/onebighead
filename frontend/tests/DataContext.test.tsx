import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, act, waitFor } from '@testing-library/react';
import { DataProvider, useData } from '../src/DataContext';
import type { Item, Category, Collection, Tenant } from '../src/types';

const mockCategories: Category[] = [
  { tenantId: 1, categoryId: 1, name: 'Test Category 1', description: 'Description 1', parentCategoryId: null, isSystem: false },
  { tenantId: 1, categoryId: 2, name: 'Test Category 2', description: 'Description 2', parentCategoryId: 1, isSystem: false },
];

const mockItems: Item[] = [
  { id: 1, tenantId: 1, categoryId: 1, name: 'Test Item 1', summary: 'Summary 1', description: 'Desc 1', properties: [], images: [] },
  { id: 2, tenantId: 1, categoryId: 2, name: 'Test Item 2', summary: 'Summary 2', description: 'Desc 2', properties: [], images: [] },
];

// Test component to access context
function TestConsumer({
  onData
}: {
  onData: (data: ReturnType<typeof useData>) => void
}) {
  const data = useData();
  onData(data);
  return <div>Test Consumer</div>;
}

describe('DataContext', () => {
  let mockItemIdCounter = 100;
  let mockCategoryIdCounter = 100;

  beforeEach(() => {
    mockItemIdCounter = 100;
    mockCategoryIdCounter = 100;
    vi.spyOn(globalThis, 'fetch').mockImplementation((url, options) => {
      const urlStr = typeof url === 'string' ? url : url.toString();
      const method = options?.method || 'GET';

      if (urlStr === '/api/categories' && method === 'GET') {
        return Promise.resolve({
          ok: true,
          json: async () => mockCategories,
        } as Response);
      }

      if (urlStr === '/api/categories' && method === 'POST') {
        const body = JSON.parse(options?.body as string);
        const newCategory = { ...body, categoryId: mockCategoryIdCounter++, isSystem: false };
        return Promise.resolve({
          ok: true,
          json: async () => newCategory,
        } as Response);
      }

      if (urlStr.match(/\/api\/categories\/\d+/) && method === 'PUT') {
        const body = JSON.parse(options?.body as string);
        return Promise.resolve({
          ok: true,
          json: async () => body,
        } as Response);
      }

      if (urlStr.match(/\/api\/categories\/\d+/) && method === 'DELETE') {
        return Promise.resolve({
          ok: true,
        } as Response);
      }
      
      if (urlStr === '/api/items' && method === 'GET') {
        return Promise.resolve({
          ok: true,
          json: async () => [...mockItems],
        } as Response);
      }

      if (urlStr === '/api/items' && method === 'POST') {
        const body = JSON.parse(options?.body as string);
        const newItem = { ...body, id: mockItemIdCounter++ };
        return Promise.resolve({
          ok: true,
          json: async () => newItem,
        } as Response);
      }

      if (urlStr.match(/\/api\/items\/\d+/) && method === 'PUT') {
        const body = JSON.parse(options?.body as string);
        return Promise.resolve({
          ok: true,
          json: async () => body,
        } as Response);
      }

      if (urlStr.match(/\/api\/items\/\d+/) && method === 'DELETE') {
        return Promise.resolve({
          ok: true,
        } as Response);
      }

      return Promise.resolve({
        ok: false,
        statusText: 'Not Found',
      } as Response);
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('DataProvider', () => {
    it('should fetch categories from API', async () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      await waitFor(() => {
        expect(contextData!.categoriesLoading).toBe(false);
      });

      expect(globalThis.fetch).toHaveBeenCalledWith('/api/categories');
      expect(contextData!.categories).toEqual(mockCategories);
      expect(contextData!.categoriesError).toBeNull();
    });

    it('should set categoriesLoading to true initially', () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      // Initially loading should be true (before fetch completes)
      expect(contextData!.categoriesLoading).toBe(true);
    });

    it('should set categoriesError on fetch failure', async () => {
      vi.spyOn(globalThis, 'fetch').mockResolvedValue({
        ok: false,
        statusText: 'Internal Server Error',
      } as Response);

      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      await waitFor(() => {
        expect(contextData!.categoriesLoading).toBe(false);
      });

      expect(contextData!.categoriesError).toBe('Failed to fetch categories: Internal Server Error');
      expect(contextData!.categories).toEqual([]);
    });

    it('should set categoriesError on network error', async () => {
      vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Network error'));

      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      await waitFor(() => {
        expect(contextData!.categoriesLoading).toBe(false);
      });

      expect(contextData!.categoriesError).toBe('Network error');
      expect(contextData!.categories).toEqual([]);
    });

    it('should provide initial items', async () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      await waitFor(() => {
        expect(contextData!.categoriesLoading).toBe(false);
      });

      expect(contextData!.items.length).toBeGreaterThan(0);
    });

    it('should provide initial collections', async () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      await waitFor(() => {
        expect(contextData!.categoriesLoading).toBe(false);
      });

      expect(contextData!.collections.length).toBeGreaterThan(0);
    });

    it('should provide initial tenants', async () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      await waitFor(() => {
        expect(contextData!.categoriesLoading).toBe(false);
      });

      expect(contextData!.tenants.length).toBeGreaterThan(0);
    });
  });

  describe('Item CRUD operations', () => {
    it('should fetch items from API', async () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      await waitFor(() => {
        expect(contextData!.itemsLoading).toBe(false);
      });

      expect(globalThis.fetch).toHaveBeenCalledWith('/api/items');
      expect(contextData!.items.length).toBe(2);
      expect(contextData!.itemsError).toBeNull();
    });

    it('should add a new item via API', async () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      await waitFor(() => {
        expect(contextData!.itemsLoading).toBe(false);
      });

      const initialLength = contextData!.items.length;

      const newItem: Item = {
        id: null,
        tenantId: 1,
        categoryId: 1,
        name: 'New Test Item',
        summary: 'Test summary',
        description: 'Test description',
        properties: [],
        images: [],
      };

      await act(async () => {
        await contextData!.addItem(newItem);
      });

      expect(contextData!.items.length).toBe(initialLength + 1);
      expect(contextData!.items.find(i => i.name === 'New Test Item')).toBeDefined();
    });

    it('should update an existing item via API', async () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      await waitFor(() => {
        expect(contextData!.itemsLoading).toBe(false);
      });

      const firstItem = contextData!.items[0];
      const originalName = firstItem.name;

      await act(async () => {
        await contextData!.updateItem(firstItem.id!, { name: 'Updated Name' });
      });

      const updatedItem = contextData!.items.find(i => i.id === firstItem.id);
      expect(updatedItem?.name).toBe('Updated Name');
      expect(updatedItem?.name).not.toBe(originalName);
    });

    it('should delete an item via API', async () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      await waitFor(() => {
        expect(contextData!.itemsLoading).toBe(false);
      });

      const initialLength = contextData!.items.length;
      const firstItemId = contextData!.items[0].id!;

      await act(async () => {
        await contextData!.deleteItem(firstItemId);
      });

      expect(contextData!.items.length).toBe(initialLength - 1);
      expect(contextData!.items.find(i => i.id === firstItemId)).toBeUndefined();
    });

    it('should generate unique IDs for new items from server', async () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      await waitFor(() => {
        expect(contextData!.itemsLoading).toBe(false);
      });

      const newItem1: Item = {
        id: null,
        tenantId: 1,
        categoryId: 1,
        name: 'Item 1',
        summary: '',
        description: '',
        properties: [],
        images: [],
      };

      const newItem2: Item = {
        id: null,
        tenantId: 1,
        categoryId: 1,
        name: 'Item 2',
        summary: '',
        description: '',
        properties: [],
        images: [],
      };

      await act(async () => {
        await contextData!.addItem(newItem1);
        await contextData!.addItem(newItem2);
      });

      const item1 = contextData!.items.find(i => i.name === 'Item 1');
      const item2 = contextData!.items.find(i => i.name === 'Item 2');

      expect(item1).toBeDefined();
      expect(item2).toBeDefined();
      expect(item1!.id).not.toBe(item2!.id);
    });
  });

  describe('Category CRUD operations', () => {
    it('should add a new category via API', async () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      await waitFor(() => {
        expect(contextData!.categoriesLoading).toBe(false);
      });

      const initialLength = contextData!.categories.length;

      const newCategory: Omit<Category, 'categoryId' | 'isSystem'> = {
        tenantId: 1,
        name: 'New Category',
        description: 'New description',
        parentCategoryId: null,
      };

      await act(async () => {
        await contextData!.addCategory(newCategory);
      });

      expect(contextData!.categories.length).toBe(initialLength + 1);
      expect(contextData!.categories.find(c => c.name === 'New Category')).toBeDefined();
      expect(globalThis.fetch).toHaveBeenCalledWith('/api/categories', expect.objectContaining({
        method: 'POST',
      }));
    });

    it('should update an existing category via API', async () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      await waitFor(() => {
        expect(contextData!.categoriesLoading).toBe(false);
      });

      const firstCategory = contextData!.categories[0];

      await act(async () => {
        await contextData!.updateCategory(firstCategory.categoryId, { name: 'Updated Category' });
      });

      const updated = contextData!.categories.find(c => c.categoryId === firstCategory.categoryId);
      expect(updated?.name).toBe('Updated Category');
      expect(globalThis.fetch).toHaveBeenCalledWith(`/api/categories/${firstCategory.categoryId}`, expect.objectContaining({
        method: 'PUT',
      }));
    });

    it('should delete a category via API', async () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      await waitFor(() => {
        expect(contextData!.categoriesLoading).toBe(false);
      });

      const initialLength = contextData!.categories.length;
      const firstCategoryId = contextData!.categories[0].categoryId;

      await act(async () => {
        await contextData!.deleteCategory(firstCategoryId);
      });

      expect(contextData!.categories.length).toBe(initialLength - 1);
      expect(globalThis.fetch).toHaveBeenCalledWith(`/api/categories/${firstCategoryId}`, expect.objectContaining({
        method: 'DELETE',
      }));
    });

    it('should refresh items after deleting a category', async () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      await waitFor(() => {
        expect(contextData!.categoriesLoading).toBe(false);
      });

      const firstCategoryId = contextData!.categories[0].categoryId;
      const initialFetchCallCount = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls.length;

      await act(async () => {
        await contextData!.deleteCategory(firstCategoryId);
      });

      // Should have called items API to refresh after delete
      const fetchCalls = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls;
      const itemsRefreshCalls = fetchCalls.slice(initialFetchCallCount).filter(
        call => call[0] === '/api/items'
      );
      expect(itemsRefreshCalls.length).toBeGreaterThan(0);
    });
  });

  describe('Collection CRUD operations', () => {
    it('should add a new collection', async () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      await waitFor(() => {
        expect(contextData!.categoriesLoading).toBe(false);
      });

      const initialLength = contextData!.collections.length;

      const newCollection: Omit<Collection, 'collectionId'> = {
        name: 'New Collection',
        tenantId: 1,
      };

      act(() => {
        contextData!.addCollection(newCollection);
      });

      expect(contextData!.collections.length).toBe(initialLength + 1);
    });

    it('should generate collectionId 1 when collections array is empty', async () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      await waitFor(() => {
        expect(contextData!.categoriesLoading).toBe(false);
      });

      // Delete all collections
      const collectionIds = contextData!.collections.map(c => c.collectionId);
      act(() => {
        collectionIds.forEach(id => contextData!.deleteCollection(id));
      });

      expect(contextData!.collections.length).toBe(0);

      // Add a new collection - should get ID 1
      const newCollection: Omit<Collection, 'collectionId'> = {
        name: 'First Collection',
        tenantId: 1,
      };

      act(() => {
        contextData!.addCollection(newCollection);
      });

      expect(contextData!.collections[0].collectionId).toBe(1);
    });

    it('should update an existing collection', async () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      await waitFor(() => {
        expect(contextData!.categoriesLoading).toBe(false);
      });

      const firstCollection = contextData!.collections[0];

      act(() => {
        contextData!.updateCollection(firstCollection.collectionId, { name: 'Updated Collection' });
      });

      const updated = contextData!.collections.find(c => c.collectionId === firstCollection.collectionId);
      expect(updated?.name).toBe('Updated Collection');
    });

    it('should delete a collection', async () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      await waitFor(() => {
        expect(contextData!.categoriesLoading).toBe(false);
      });

      const initialLength = contextData!.collections.length;
      const firstCollectionId = contextData!.collections[0].collectionId;

      act(() => {
        contextData!.deleteCollection(firstCollectionId);
      });

      expect(contextData!.collections.length).toBe(initialLength - 1);
    });
  });

  describe('Tenant CRUD operations', () => {
    it('should add a new tenant', async () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      await waitFor(() => {
        expect(contextData!.categoriesLoading).toBe(false);
      });

      const initialLength = contextData!.tenants.length;

      const newTenant: Omit<Tenant, 'tenantId'> = {
        name: 'New Tenant',
        owner: 'owner@example.com',
      };

      act(() => {
        contextData!.addTenant(newTenant);
      });

      expect(contextData!.tenants.length).toBe(initialLength + 1);
    });

    it('should generate tenantId 1 when tenants array is empty', async () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      await waitFor(() => {
        expect(contextData!.categoriesLoading).toBe(false);
      });

      // Delete all tenants
      const tenantIds = contextData!.tenants.map(t => t.tenantId);
      act(() => {
        tenantIds.forEach(id => contextData!.deleteTenant(id));
      });

      expect(contextData!.tenants.length).toBe(0);

      // Add a new tenant - should get ID 1
      const newTenant: Omit<Tenant, 'tenantId'> = {
        name: 'First Tenant',
        owner: 'first@example.com',
      };

      act(() => {
        contextData!.addTenant(newTenant);
      });

      expect(contextData!.tenants[0].tenantId).toBe(1);
    });

    it('should update an existing tenant', async () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      await waitFor(() => {
        expect(contextData!.categoriesLoading).toBe(false);
      });

      const firstTenant = contextData!.tenants[0];

      act(() => {
        contextData!.updateTenant(firstTenant.tenantId, { name: 'Updated Tenant' });
      });

      const updated = contextData!.tenants.find(t => t.tenantId === firstTenant.tenantId);
      expect(updated?.name).toBe('Updated Tenant');
    });

    it('should delete a tenant', async () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      await waitFor(() => {
        expect(contextData!.categoriesLoading).toBe(false);
      });

      const initialLength = contextData!.tenants.length;
      const firstTenantId = contextData!.tenants[0].tenantId;

      act(() => {
        contextData!.deleteTenant(firstTenantId);
      });

      expect(contextData!.tenants.length).toBe(initialLength - 1);
    });
  });

  describe('useData hook', () => {
    it('should return context value when used within provider', () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      expect(contextData).toHaveProperty('categories');
      expect(contextData).toHaveProperty('items');
      expect(contextData).toHaveProperty('collections');
      expect(contextData).toHaveProperty('tenants');
      expect(contextData).toHaveProperty('addItem');
      expect(contextData).toHaveProperty('updateItem');
      expect(contextData).toHaveProperty('deleteItem');
      expect(contextData).toHaveProperty('addCategory');
      expect(contextData).toHaveProperty('updateCategory');
      expect(contextData).toHaveProperty('deleteCategory');
      expect(contextData).toHaveProperty('addCollection');
      expect(contextData).toHaveProperty('updateCollection');
      expect(contextData).toHaveProperty('deleteCollection');
      expect(contextData).toHaveProperty('addTenant');
      expect(contextData).toHaveProperty('updateTenant');
      expect(contextData).toHaveProperty('deleteTenant');
    });

    it('should return default context values when used without provider', async () => {
      let contextData: ReturnType<typeof useData> | null = null;

      // Render without DataProvider - uses default context value
      render(<TestConsumer onData={(data) => { contextData = data; }} />);

      expect(contextData!.categories).toEqual([]);
      expect(contextData!.items).toEqual([]);
      expect(contextData!.collections).toEqual([]);
      expect(contextData!.tenants).toEqual([]);

      // Default async functions should be callable and return promises
      await expect(contextData!.addItem({} as Item)).resolves.toBe(0);
      await expect(contextData!.updateItem(1, {})).resolves.toBeUndefined();
      await expect(contextData!.deleteItem(1)).resolves.toBeUndefined();
      await expect(contextData!.refreshItems()).resolves.toBeUndefined();
      contextData!.addCategory({} as Omit<Category, 'categoryId'>);
      contextData!.updateCategory(1, {});
      contextData!.deleteCategory(1);
      contextData!.addCollection({} as Omit<Collection, 'collectionId'>);
      contextData!.updateCollection(1, {});
      contextData!.deleteCollection(1);
      contextData!.addTenant({} as Omit<Tenant, 'tenantId'>);
      contextData!.updateTenant(1, {});
      contextData!.deleteTenant(1);
    });
  });
});

