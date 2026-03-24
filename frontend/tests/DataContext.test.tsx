import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, act } from '@testing-library/react';
import { DataProvider } from '../src/contexts/DataContext';
import { useData } from '../src/contexts/useData';
import type { Item, Category, Collection, PublishResponse, UnpublishResponse, BulkPublishResponse, BulkUnpublishResponse, UnpublishPreviewResponse } from '../src/utils/types';
import { UserFlag, Visibility } from '../src/utils/types';

const mockCollections: Collection[] = [
  { collectionId: 1, workspaceId: 1, name: 'Test Collection', description: 'Test desc', heroImageUrl: null, slug: 'test', visibility: Visibility.Public, effectiveIsPublic: true },
];

const mockCategories: Category[] = [
  { workspaceId: 1, categoryId: 1, collectionId: 1, name: 'Test Category 1', description: 'Description 1', parentCategoryId: null, isSystem: false, visibility: Visibility.Private, effectiveIsPublic: true, itemTemplateIds: [] },
  { workspaceId: 1, categoryId: 2, collectionId: 1, name: 'Test Category 2', description: 'Description 2', parentCategoryId: 1, isSystem: false, visibility: Visibility.Private, effectiveIsPublic: true, itemTemplateIds: [] },
];

const mockItems: Item[] = [
  { id: 1, workspaceId: 1, collectionId: 1, categoryId: 1, templateKey: null, name: 'Test Item 1', summary: 'Summary 1', description: 'Desc 1', properties: [], images: [], visibility: Visibility.Private, effectiveIsPublic: true, userFlag: UserFlag.Have },
  { id: 2, workspaceId: 1, collectionId: 1, categoryId: 2, templateKey: null, name: 'Test Item 2', summary: 'Summary 2', description: 'Desc 2', properties: [], images: [], visibility: Visibility.Private, effectiveIsPublic: true, userFlag: UserFlag.Have },
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
  let mockCollectionIdCounter = 100;

  beforeEach(() => {
    mockItemIdCounter = 100;
    mockCategoryIdCounter = 100;
    mockCollectionIdCounter = 100;
    vi.spyOn(globalThis, 'fetch').mockImplementation((url, options) => {
      const urlStr = typeof url === 'string' ? url : url.toString();
      const method = options?.method || 'GET';

      // Collections
      if (urlStr === '/api/collections' && method === 'GET') {
        return Promise.resolve({
          ok: true,
          json: async () => mockCollections,
        } as Response);
      }

      if (urlStr === '/api/collections' && method === 'POST') {
        const body = JSON.parse(options?.body as string);
        const newCollection = { ...body, collectionId: mockCollectionIdCounter++, workspaceId: 1, slug: 'new' };
        return Promise.resolve({
          ok: true,
          json: async () => newCollection,
        } as Response);
      }

      if (urlStr.match(/\/api\/collections\/\d+$/) && method === 'PUT') {
        const body = JSON.parse(options?.body as string);
        return Promise.resolve({
          ok: true,
          json: async () => ({ ...mockCollections[0], ...body }),
        } as Response);
      }

      if (urlStr.match(/\/api\/collections\/\d+$/) && method === 'DELETE') {
        return Promise.resolve({ ok: true, status: 204 } as Response);
      }

      // Categories
      if (urlStr.includes('/api/categories') && method === 'GET') {
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
          json: async () => ({ ...mockCategories[0], ...body }),
        } as Response);
      }

      if (urlStr.match(/\/api\/categories\/\d+/) && method === 'DELETE') {
        return Promise.resolve({ ok: true, status: 204 } as Response);
      }

      // Items
      if (urlStr.includes('/api/items') && method === 'GET') {
        return Promise.resolve({
          ok: true,
          headers: new Headers({ 'ETag': '"test-etag"' }),
          json: async () => mockItems,
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
        return Promise.resolve({ ok: true, status: 204 } as Response);
      }

      // Property suggestions
      if (urlStr.includes('/property-suggestions') && method === 'GET') {
        return Promise.resolve({
          ok: true,
          json: async () => ({ categories: [], names: [] }),
        } as Response);
      }

      if (urlStr.includes('/property-suggestions/sync') && method === 'POST') {
        return Promise.resolve({
          ok: true,
          json: async () => ({ categories: [], names: [] }),
        } as Response);
      }

      // Image upload
      if (urlStr === '/api/images' && method === 'POST') {
        const key = 'test-image-key-' + Math.random().toString(36).substr(2, 9);
        return Promise.resolve({
          ok: true,
          json: async () => ({ key, url: `/api/images/${key}` }),
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
    it('should provide default context values', () => {
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      expect(capturedData).not.toBeNull();
      expect(capturedData!.collections).toEqual([]);
      expect(capturedData!.categories).toEqual([]);
      expect(capturedData!.items).toEqual([]);
      expect(capturedData!.currentCollection).toBeNull();
    });

    it('should load collections from API', async () => {
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      await act(async () => {
        await capturedData!.loadCollections();
      });

      expect(capturedData!.collections).toHaveLength(1);
      expect(capturedData!.collections[0].name).toBe('Test Collection');
    });

    it('should load categories for collection', async () => {
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      await act(async () => {
        await capturedData!.loadCategoriesForCollection(1);
      });

      expect(capturedData!.categories).toHaveLength(2);
    });

    it('should load items for category', async () => {
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      await act(async () => {
        await capturedData!.loadItemsForCategory(1);
      });

      expect(capturedData!.items).toHaveLength(2);
    });
  });

  describe('Collection CRUD operations', () => {
    it('should add a new collection', async () => {
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      await act(async () => {
        await capturedData!.addCollection('New Collection', 'New description');
      });

      expect(capturedData!.collections).toHaveLength(1);
      expect(capturedData!.collections[0].name).toBe('New Collection');
    });

    it('should update a collection', async () => {
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      await act(async () => {
        await capturedData!.loadCollections();
      });

      await act(async () => {
        await capturedData!.updateCollection(1, { name: 'Updated Name' });
      });

      expect(capturedData!.collections[0].name).toBe('Updated Name');
    });

    it('should delete a collection', async () => {
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      await act(async () => {
        await capturedData!.loadCollections();
      });

      expect(capturedData!.collections).toHaveLength(1);

      await act(async () => {
        await capturedData!.deleteCollection(1);
      });

      expect(capturedData!.collections).toHaveLength(0);
    });
  });

  describe('Category CRUD operations', () => {
    it('should add a new category', async () => {
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      const categoryId = await act(async () => {
        return capturedData!.addCategory({ collectionId: 1, name: 'New Category' });
      });

      expect(categoryId).toBe(100);
      expect(capturedData!.categories).toHaveLength(1);
    });

    it('should update a category', async () => {
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      await act(async () => {
        await capturedData!.loadCategoriesForCollection(1);
      });

      await act(async () => {
        await capturedData!.updateCategory(1, { name: 'Updated Category' });
      });

      expect(capturedData!.categories.find(c => c.categoryId === 1)?.name).toBe('Updated Category');
    });

    it('should delete a category', async () => {
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      await act(async () => {
        await capturedData!.loadCategoriesForCollection(1);
      });

      expect(capturedData!.categories).toHaveLength(2);

      await act(async () => {
        await capturedData!.deleteCategory(1);
      });

      expect(capturedData!.categories).toHaveLength(1);
    });
  });

  describe('Item CRUD operations', () => {
    it('should add a new item', async () => {
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      const newItem: Item = {
        id: null,
        workspaceId: 1,
        collectionId: 1,
        categoryId: 1,
        templateKey: null,
        name: 'New Item',
        summary: 'Summary',
        description: 'Description',
        properties: [],
        images: [],
        visibility: Visibility.Private,
        effectiveIsPublic: false,
        userFlag: UserFlag.Have,
      };

      const itemId = await act(async () => {
        return capturedData!.addItem(newItem);
      });

      expect(itemId).toBe(100);
      expect(capturedData!.items).toHaveLength(1);
    });

    it('should update an item', async () => {
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      await act(async () => {
        await capturedData!.loadItemsForCategory(1);
      });

      await act(async () => {
        await capturedData!.updateItem(1, { name: 'Updated Item' });
      });

      expect(capturedData!.items.find(i => i.id === 1)?.name).toBe('Updated Item');
    });

    it('should delete an item', async () => {
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      await act(async () => {
        await capturedData!.loadItemsForCategory(1);
      });

      expect(capturedData!.items).toHaveLength(2);

      await act(async () => {
        await capturedData!.deleteItem(1);
      });

      expect(capturedData!.items).toHaveLength(1);
    });

    it('should include userFlag when adding a new item', async () => {
      let capturedRequestBody: string | null = null;

      vi.spyOn(globalThis, 'fetch').mockImplementation((url, options) => {
        const urlStr = typeof url === 'string' ? url : url.toString();
        const method = options?.method || 'GET';

        if (urlStr === '/api/items' && method === 'POST') {
          capturedRequestBody = options?.body as string;
          const body = JSON.parse(capturedRequestBody);
          const newItem = { ...body, id: 100 };
          return Promise.resolve({
            ok: true,
            json: async () => newItem,
          } as Response);
        }

        if (urlStr.includes('/property-suggestions/sync') && method === 'POST') {
          return Promise.resolve({
            ok: true,
            json: async () => ({ categories: [], names: [] }),
          } as Response);
        }

        return Promise.resolve({ ok: false, statusText: 'Not Found' } as Response);
      });

      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      const newItem: Item = {
        id: null,
        workspaceId: 1,
        collectionId: 1,
        categoryId: 1,
        templateKey: null,
        name: 'New Item with Flag',
        summary: 'Summary',
        description: 'Description',
        properties: [],
        images: [],
        visibility: Visibility.Private,
        effectiveIsPublic: true,
        userFlag: UserFlag.Want,
      };

      await act(async () => {
        await capturedData!.addItem(newItem);
      });

      expect(capturedRequestBody).not.toBeNull();
      const parsedBody = JSON.parse(capturedRequestBody!);
      expect(parsedBody.userFlag).toBe(UserFlag.Want);
    });

    it('should include userFlag when updating an item', async () => {
      let capturedRequestBody: string | null = null;

      vi.spyOn(globalThis, 'fetch').mockImplementation((url, options) => {
        const urlStr = typeof url === 'string' ? url : url.toString();
        const method = options?.method || 'GET';

        if (urlStr.includes('/api/items') && method === 'GET') {
          return Promise.resolve({
            ok: true,
            headers: new Headers({ 'ETag': '"test-etag"' }),
            json: async () => mockItems,
          } as Response);
        }

        if (urlStr.match(/\/api\/items\/\d+/) && method === 'PUT') {
          capturedRequestBody = options?.body as string;
          const body = JSON.parse(capturedRequestBody);
          return Promise.resolve({
            ok: true,
            json: async () => body,
          } as Response);
        }

        if (urlStr.includes('/property-suggestions/sync') && method === 'POST') {
          return Promise.resolve({
            ok: true,
            json: async () => ({ categories: [], names: [] }),
          } as Response);
        }

        return Promise.resolve({ ok: false, statusText: 'Not Found' } as Response);
      });

      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      await act(async () => {
        await capturedData!.loadItemsForCategory(1);
      });

      await act(async () => {
        await capturedData!.updateItem(1, { userFlag: UserFlag.TradeOrSell });
      });

      expect(capturedRequestBody).not.toBeNull();
      const parsedBody = JSON.parse(capturedRequestBody!);
      expect(parsedBody.userFlag).toBe(UserFlag.TradeOrSell);
    });
  });

  describe('Property suggestions', () => {
    it('should load property suggestions', async () => {
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      await act(async () => {
        await capturedData!.loadPropertySuggestions(1);
      });

      expect(capturedData!.propertyCategorySuggestions).toEqual([]);
      expect(capturedData!.propertyNameSuggestions).toEqual([]);
    });

    it('should sync property suggestions', async () => {
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      await act(async () => {
        await capturedData!.syncPropertySuggestions(1);
      });

      expect(capturedData!.propertyCategorySuggestions).toEqual([]);
      expect(capturedData!.propertyNameSuggestions).toEqual([]);
    });

    it('should add local category suggestion', async () => {
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      act(() => {
        capturedData!.addLocalCategorySuggestion('NewCategory');
      });

      expect(capturedData!.propertyCategorySuggestions).toContain('NewCategory');
    });

    it('should add local name suggestion', async () => {
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      act(() => {
        capturedData!.addLocalNameSuggestion('NewName');
      });

      expect(capturedData!.propertyNameSuggestions).toContain('NewName');
    });

    it('should not add duplicate local category suggestion', async () => {
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      act(() => {
        capturedData!.addLocalCategorySuggestion('TestCategory');
        capturedData!.addLocalCategorySuggestion('TestCategory');
      });

      const count = capturedData!.propertyCategorySuggestions.filter(c => c === 'TestCategory').length;
      expect(count).toBe(1);
    });

    it('should not add empty local suggestion', async () => {
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      act(() => {
        capturedData!.addLocalCategorySuggestion('');
        capturedData!.addLocalCategorySuggestion('   ');
      });

      expect(capturedData!.propertyCategorySuggestions).toHaveLength(0);
    });

    it('should sort local suggestions alphabetically', async () => {
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      act(() => {
        capturedData!.addLocalCategorySuggestion('Zebra');
        capturedData!.addLocalCategorySuggestion('Apple');
        capturedData!.addLocalCategorySuggestion('Mango');
      });

      expect(capturedData!.propertyCategorySuggestions).toEqual(['Apple', 'Mango', 'Zebra']);
    });
  });

  describe('Image upload', () => {
    it('should upload image and return key and url', async () => {
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      const file = new File(['fake image content'], 'test.jpg', { type: 'image/jpeg' });

      const result = await act(async () => {
        return capturedData!.uploadImage(file);
      });

      expect(result.key).toBeDefined();
      expect(result.url).toContain('/api/images/');
    });

    it('should send file as FormData', async () => {
      let capturedData: ReturnType<typeof useData> | null = null;
      let capturedBody: FormData | null = null;

      vi.spyOn(globalThis, 'fetch').mockImplementation((_url, options) => {
        if (options?.body instanceof FormData) {
          capturedBody = options.body;
        }
        return Promise.resolve({
          ok: true,
          json: async () => ({ key: 'test-key', url: '/api/images/test-key' }),
        } as Response);
      });

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      const file = new File(['content'], 'test.jpg', { type: 'image/jpeg' });

      await act(async () => {
        await capturedData!.uploadImage(file);
      });

      expect(capturedBody).toBeInstanceOf(FormData);
      expect(capturedBody!.get('file')).toBe(file);
    });

    it('should throw error on upload failure', async () => {
      let capturedData: ReturnType<typeof useData> | null = null;

      vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
        return Promise.resolve({
          ok: false,
          status: 400,
          statusText: 'Bad Request',
          text: async () => JSON.stringify({ error: 'Invalid file type' }),
        } as Response);
      });

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      const file = new File(['content'], 'test.txt', { type: 'text/plain' });

      await expect(act(async () => {
        await capturedData!.uploadImage(file);
      })).rejects.toThrow('Invalid file type');
    });

    it('should handle server error message', async () => {
      let capturedData: ReturnType<typeof useData> | null = null;

      vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
        return Promise.resolve({
          ok: false,
          status: 500,
          statusText: 'Internal Server Error',
          text: async () => JSON.stringify({ error: 'File content does not match the declared file type' }),
        } as Response);
      });

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      const file = new File(['content'], 'fake.jpg', { type: 'image/jpeg' });

      await expect(act(async () => {
        await capturedData!.uploadImage(file);
      })).rejects.toThrow('File content does not match the declared file type');
    });

    it('should fallback to status text when no error in response', async () => {
      let capturedData: ReturnType<typeof useData> | null = null;

      vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
        return Promise.resolve({
          ok: false,
          status: 401,
          statusText: 'Unauthorized',
          text: async () => '',
        } as Response);
      });

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      const file = new File(['content'], 'test.jpg', { type: 'image/jpeg' });

      await expect(act(async () => {
        await capturedData!.uploadImage(file);
      })).rejects.toThrow('Unauthorized');
    });
  });

  describe('Publish/unpublish operations', () => {
    const mockPublishResponse: PublishResponse = {
      published: { type: 'Item', id: 1, name: 'Test Item' },
      promoted: [],
      childrenPublished: 0,
      requiresSlugSetup: false,
    };

    const mockUnpublishResponse: UnpublishResponse = {
      unpublished: { type: 'Item', id: 1, name: 'Test Item' },
      affectedPublicItems: 0,
      affectedPublicCategories: 0,
    };

    const mockBulkPublishResponse: BulkPublishResponse = {
      publishedCount: 2,
      promoted: [],
      requiresSlugSetup: false,
    };

    const mockBulkUnpublishResponse: BulkUnpublishResponse = {
      unpublishedCount: 2,
    };

    const mockUnpublishPreview: UnpublishPreviewResponse = {
      affectedPublicItems: 3,
      affectedPublicCategories: 1,
    };

    function setupPublishMock() {
      vi.spyOn(globalThis, 'fetch').mockImplementation((url, options) => {
        const urlStr = typeof url === 'string' ? url : url.toString();
        const method = options?.method || 'GET';

        // Publish item
        if (urlStr.match(/\/api\/workspaces\/\d+\/items\/\d+\/publish/) && method === 'POST') {
          return Promise.resolve({
            ok: true,
            json: async () => mockPublishResponse,
          } as Response);
        }

        // Unpublish item
        if (urlStr.match(/\/api\/workspaces\/\d+\/items\/\d+\/unpublish/) && method === 'POST') {
          return Promise.resolve({
            ok: true,
            json: async () => mockUnpublishResponse,
          } as Response);
        }

        // Bulk publish
        if (urlStr.match(/\/api\/workspaces\/\d+\/items\/bulk-publish/) && method === 'POST') {
          return Promise.resolve({
            ok: true,
            json: async () => mockBulkPublishResponse,
          } as Response);
        }

        // Bulk unpublish
        if (urlStr.match(/\/api\/workspaces\/\d+\/items\/bulk-unpublish/) && method === 'POST') {
          return Promise.resolve({
            ok: true,
            json: async () => mockBulkUnpublishResponse,
          } as Response);
        }

        // Publish category
        if (urlStr.match(/\/api\/workspaces\/\d+\/categories\/\d+\/publish/) && method === 'POST') {
          return Promise.resolve({
            ok: true,
            json: async () => mockPublishResponse,
          } as Response);
        }

        // Unpublish category
        if (urlStr.match(/\/api\/workspaces\/\d+\/categories\/\d+\/unpublish$/) && method === 'POST') {
          return Promise.resolve({
            ok: true,
            json: async () => mockUnpublishResponse,
          } as Response);
        }

        // Unpublish category preview
        if (urlStr.match(/\/api\/workspaces\/\d+\/categories\/\d+\/unpublish-preview/) && method === 'GET') {
          return Promise.resolve({
            ok: true,
            json: async () => mockUnpublishPreview,
          } as Response);
        }

        // Publish collection
        if (urlStr.match(/\/api\/workspaces\/\d+\/collections\/\d+\/publish/) && method === 'POST') {
          return Promise.resolve({
            ok: true,
            json: async () => mockPublishResponse,
          } as Response);
        }

        // Unpublish collection
        if (urlStr.match(/\/api\/workspaces\/\d+\/collections\/\d+\/unpublish$/) && method === 'POST') {
          return Promise.resolve({
            ok: true,
            json: async () => mockUnpublishResponse,
          } as Response);
        }

        // Unpublish collection preview
        if (urlStr.match(/\/api\/workspaces\/\d+\/collections\/\d+\/unpublish-preview/) && method === 'GET') {
          return Promise.resolve({
            ok: true,
            json: async () => mockUnpublishPreview,
          } as Response);
        }

        // Items (for refresh after publish)
        if (urlStr.includes('/api/items') && method === 'GET') {
          return Promise.resolve({
            ok: true,
            headers: new Headers({ 'ETag': '"test-etag"' }),
            json: async () => mockItems,
          } as Response);
        }

        // Categories (for refresh after publish)
        if (urlStr.includes('/api/categories') && method === 'GET') {
          return Promise.resolve({
            ok: true,
            json: async () => mockCategories,
          } as Response);
        }

        // Collections (for refresh after publish)
        if (urlStr === '/api/collections' && method === 'GET') {
          return Promise.resolve({
            ok: true,
            json: async () => mockCollections,
          } as Response);
        }

        return Promise.resolve({ ok: false, statusText: 'Not Found' } as Response);
      });
    }

    it('should publish an item', async () => {
      setupPublishMock();
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      // Set current collection so we have a workspaceId
      act(() => {
        capturedData!.setCurrentCollection(mockCollections[0]);
      });

      const result = await act(async () => {
        return capturedData!.publishItem(1);
      });

      expect(result).toEqual(mockPublishResponse);
    });

    it('should unpublish an item', async () => {
      setupPublishMock();
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      act(() => {
        capturedData!.setCurrentCollection(mockCollections[0]);
      });

      const result = await act(async () => {
        return capturedData!.unpublishItem(1);
      });

      expect(result).toEqual(mockUnpublishResponse);
    });

    it('should bulk publish items', async () => {
      setupPublishMock();
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      act(() => {
        capturedData!.setCurrentCollection(mockCollections[0]);
      });

      const result = await act(async () => {
        return capturedData!.bulkPublishItems([1, 2]);
      });

      expect(result).toEqual(mockBulkPublishResponse);
    });

    it('should bulk unpublish items', async () => {
      setupPublishMock();
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      act(() => {
        capturedData!.setCurrentCollection(mockCollections[0]);
      });

      const result = await act(async () => {
        return capturedData!.bulkUnpublishItems([1, 2]);
      });

      expect(result).toEqual(mockBulkUnpublishResponse);
    });

    it('should publish a category', async () => {
      setupPublishMock();
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      act(() => {
        capturedData!.setCurrentCollection(mockCollections[0]);
      });

      const result = await act(async () => {
        return capturedData!.publishCategory(1, true);
      });

      expect(result).toEqual(mockPublishResponse);
    });

    it('should unpublish a category', async () => {
      setupPublishMock();
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      act(() => {
        capturedData!.setCurrentCollection(mockCollections[0]);
      });

      const result = await act(async () => {
        return capturedData!.unpublishCategory(1);
      });

      expect(result).toEqual(mockUnpublishResponse);
    });

    it('should publish a collection', async () => {
      setupPublishMock();
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      act(() => {
        capturedData!.setCurrentCollection(mockCollections[0]);
      });

      const result = await act(async () => {
        return capturedData!.publishCollection(1, false);
      });

      expect(result).toEqual(mockPublishResponse);
    });

    it('should unpublish a collection', async () => {
      setupPublishMock();
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      act(() => {
        capturedData!.setCurrentCollection(mockCollections[0]);
      });

      const result = await act(async () => {
        return capturedData!.unpublishCollection(1);
      });

      expect(result).toEqual(mockUnpublishResponse);
    });

    it('should get unpublish category preview', async () => {
      setupPublishMock();
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      act(() => {
        capturedData!.setCurrentCollection(mockCollections[0]);
      });

      const result = await act(async () => {
        return capturedData!.getUnpublishCategoryPreview(1);
      });

      expect(result).toEqual(mockUnpublishPreview);
    });

    it('should get unpublish collection preview', async () => {
      setupPublishMock();
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      act(() => {
        capturedData!.setCurrentCollection(mockCollections[0]);
      });

      const result = await act(async () => {
        return capturedData!.getUnpublishCollectionPreview(1);
      });

      expect(result).toEqual(mockUnpublishPreview);
    });

    it('should throw when no collection is set', async () => {
      setupPublishMock();
      let capturedData: ReturnType<typeof useData> | null = null;

      render(
        <DataProvider>
          <TestConsumer onData={(data) => { capturedData = data; }} />
        </DataProvider>
      );

      await expect(act(async () => {
        await capturedData!.publishItem(1);
      })).rejects.toThrow('No active collection to determine workspace');
    });
  });
});
