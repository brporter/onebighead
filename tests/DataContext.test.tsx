import { describe, it, expect } from 'vitest';
import { render, act } from '@testing-library/react';
import { DataProvider, useData } from '../src/DataContext';
import type { Item, Category, Collection, Tenant } from '../src/types';

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
  describe('DataProvider', () => {
    it('should provide initial categories', () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      expect(contextData).not.toBeNull();
      expect(contextData!.categories.length).toBeGreaterThan(0);
    });

    it('should provide initial items', () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      expect(contextData!.items.length).toBeGreaterThan(0);
    });

    it('should provide initial collections', () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      expect(contextData!.collections.length).toBeGreaterThan(0);
    });

    it('should provide initial tenants', () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      expect(contextData!.tenants.length).toBeGreaterThan(0);
    });
  });

  describe('Item CRUD operations', () => {
    it('should add a new item', () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

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

      act(() => {
        contextData!.addItem(newItem);
      });

      expect(contextData!.items.length).toBe(initialLength + 1);
      expect(contextData!.items.find(i => i.name === 'New Test Item')).toBeDefined();
    });

    it('should generate ID 1 when items array is empty', () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      // First, delete all existing items
      const itemIds = contextData!.items.map(i => i.id!);
      act(() => {
        itemIds.forEach(id => contextData!.deleteItem(id));
      });

      expect(contextData!.items.length).toBe(0);

      // Now add a new item - should get ID 1
      const newItem: Item = {
        id: null,
        tenantId: 1,
        categoryId: 1,
        name: 'First Item',
        summary: '',
        description: '',
        properties: [],
        images: [],
      };

      act(() => {
        contextData!.addItem(newItem);
      });

      // The new item should have ID 1
      expect(contextData!.items[0].id).toBe(1);
    });

    it('should update an existing item', () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      const firstItem = contextData!.items[0];
      const originalName = firstItem.name;

      act(() => {
        contextData!.updateItem(firstItem.id!, { name: 'Updated Name' });
      });

      const updatedItem = contextData!.items.find(i => i.id === firstItem.id);
      expect(updatedItem?.name).toBe('Updated Name');
      expect(updatedItem?.name).not.toBe(originalName);
    });

    it('should delete an item', () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      const initialLength = contextData!.items.length;
      const firstItemId = contextData!.items[0].id!;

      act(() => {
        contextData!.deleteItem(firstItemId);
      });

      expect(contextData!.items.length).toBe(initialLength - 1);
      expect(contextData!.items.find(i => i.id === firstItemId)).toBeUndefined();
    });

    it('should generate unique IDs for new items', () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

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

      let id1: number, id2: number;

      act(() => {
        id1 = contextData!.addItem(newItem1);
      });

      act(() => {
        id2 = contextData!.addItem(newItem2);
      });

      expect(id1!).not.toBe(id2!);
    });
  });

  describe('Category CRUD operations', () => {
    it('should add a new category', () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      const initialLength = contextData!.categories.length;

      const newCategory: Omit<Category, 'categoryId'> = {
        tenantId: 1,
        name: 'New Category',
        description: 'New description',
        parentCategoryId: null,
      };

      act(() => {
        contextData!.addCategory(newCategory);
      });

      expect(contextData!.categories.length).toBe(initialLength + 1);
      expect(contextData!.categories.find(c => c.name === 'New Category')).toBeDefined();
    });

    it('should generate categoryId 1 when categories array is empty', () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      // Delete all categories
      const categoryIds = contextData!.categories.map(c => c.categoryId);
      act(() => {
        categoryIds.forEach(id => contextData!.deleteCategory(id));
      });

      expect(contextData!.categories.length).toBe(0);

      // Add a new category - should get ID 1
      const newCategory: Omit<Category, 'categoryId'> = {
        tenantId: 1,
        name: 'First Category',
        description: 'desc',
        parentCategoryId: null,
      };

      act(() => {
        contextData!.addCategory(newCategory);
      });

      expect(contextData!.categories[0].categoryId).toBe(1);
    });

    it('should update an existing category', () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      const firstCategory = contextData!.categories[0];

      act(() => {
        contextData!.updateCategory(firstCategory.categoryId, { name: 'Updated Category' });
      });

      const updated = contextData!.categories.find(c => c.categoryId === firstCategory.categoryId);
      expect(updated?.name).toBe('Updated Category');
    });

    it('should delete a category', () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      const initialLength = contextData!.categories.length;
      const firstCategoryId = contextData!.categories[0].categoryId;

      act(() => {
        contextData!.deleteCategory(firstCategoryId);
      });

      expect(contextData!.categories.length).toBe(initialLength - 1);
    });
  });

  describe('Collection CRUD operations', () => {
    it('should add a new collection', () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

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

    it('should generate collectionId 1 when collections array is empty', () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

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

    it('should update an existing collection', () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      const firstCollection = contextData!.collections[0];

      act(() => {
        contextData!.updateCollection(firstCollection.collectionId, { name: 'Updated Collection' });
      });

      const updated = contextData!.collections.find(c => c.collectionId === firstCollection.collectionId);
      expect(updated?.name).toBe('Updated Collection');
    });

    it('should delete a collection', () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      const initialLength = contextData!.collections.length;
      const firstCollectionId = contextData!.collections[0].collectionId;

      act(() => {
        contextData!.deleteCollection(firstCollectionId);
      });

      expect(contextData!.collections.length).toBe(initialLength - 1);
    });
  });

  describe('Tenant CRUD operations', () => {
    it('should add a new tenant', () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

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

    it('should generate tenantId 1 when tenants array is empty', () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

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

    it('should update an existing tenant', () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

      const firstTenant = contextData!.tenants[0];

      act(() => {
        contextData!.updateTenant(firstTenant.tenantId, { name: 'Updated Tenant' });
      });

      const updated = contextData!.tenants.find(t => t.tenantId === firstTenant.tenantId);
      expect(updated?.name).toBe('Updated Tenant');
    });

    it('should delete a tenant', () => {
      let contextData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { contextData = data; }} />
        </DataProvider>
      );

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

    it('should return default context values when used without provider', () => {
      let contextData: ReturnType<typeof useData> | null = null;

      // Render without DataProvider - uses default context value
      render(<TestConsumer onData={(data) => { contextData = data; }} />);

      expect(contextData!.categories).toEqual([]);
      expect(contextData!.items).toEqual([]);
      expect(contextData!.collections).toEqual([]);
      expect(contextData!.tenants).toEqual([]);

      // Default functions should be callable
      expect(contextData!.addItem({} as Item)).toBe(0);
      contextData!.updateItem(1, {});
      contextData!.deleteItem(1);
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

