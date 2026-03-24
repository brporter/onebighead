import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { publishApi } from '../../src/api/publish';

describe('publishApi', () => {
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockFetch = vi.fn();
    vi.stubGlobal('fetch', mockFetch);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('publishItem', () => {
    it('should POST to publish item endpoint', async () => {
      const mockResponse = {
        published: { type: 'Item', id: 1, name: 'Test Item' },
        promoted: [],
        childrenPublished: 0,
        requiresSlugSetup: false,
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockResponse,
      });

      const result = await publishApi.publishItem(1, 42);

      const call = mockFetch.mock.calls[0];
      expect(call[0]).toBe('/api/workspaces/1/items/42/publish');
      expect(call[1].method).toBe('POST');
      expect(result).toEqual(mockResponse);
    });
  });

  describe('unpublishItem', () => {
    it('should POST to unpublish item endpoint', async () => {
      const mockResponse = {
        unpublished: { type: 'Item', id: 42, name: 'Test Item' },
        affectedPublicItems: 0,
        affectedPublicCategories: 0,
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockResponse,
      });

      const result = await publishApi.unpublishItem(1, 42);

      const call = mockFetch.mock.calls[0];
      expect(call[0]).toBe('/api/workspaces/1/items/42/unpublish');
      expect(call[1].method).toBe('POST');
      expect(result).toEqual(mockResponse);
    });
  });

  describe('publishCategory', () => {
    it('should POST to publish category endpoint with includeChildren', async () => {
      const mockResponse = {
        published: { type: 'Category', id: 5, name: 'Test Category' },
        promoted: [],
        childrenPublished: 3,
        requiresSlugSetup: false,
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockResponse,
      });

      const result = await publishApi.publishCategory(1, 5, true);

      const call = mockFetch.mock.calls[0];
      expect(call[0]).toBe('/api/workspaces/1/categories/5/publish');
      expect(call[1].method).toBe('POST');
      expect(JSON.parse(call[1].body)).toEqual({ includeChildren: true });
      expect(result).toEqual(mockResponse);
    });

    it('should POST with includeChildren false', async () => {
      const mockResponse = {
        published: { type: 'Category', id: 5, name: 'Test Category' },
        promoted: [],
        childrenPublished: 0,
        requiresSlugSetup: false,
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockResponse,
      });

      await publishApi.publishCategory(1, 5, false);

      const call = mockFetch.mock.calls[0];
      expect(JSON.parse(call[1].body)).toEqual({ includeChildren: false });
    });
  });

  describe('unpublishCategory', () => {
    it('should POST to unpublish category endpoint', async () => {
      const mockResponse = {
        unpublished: { type: 'Category', id: 5, name: 'Test Category' },
        affectedPublicItems: 10,
        affectedPublicCategories: 2,
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockResponse,
      });

      const result = await publishApi.unpublishCategory(1, 5);

      const call = mockFetch.mock.calls[0];
      expect(call[0]).toBe('/api/workspaces/1/categories/5/unpublish');
      expect(call[1].method).toBe('POST');
      expect(result).toEqual(mockResponse);
    });
  });

  describe('unpublishCategoryPreview', () => {
    it('should GET unpublish category preview', async () => {
      const mockResponse = {
        affectedPublicItems: 10,
        affectedPublicCategories: 2,
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockResponse,
      });

      const result = await publishApi.unpublishCategoryPreview(1, 5);

      const call = mockFetch.mock.calls[0];
      expect(call[0]).toBe('/api/workspaces/1/categories/5/unpublish-preview');
      expect(call[1].method).toBe('GET');
      expect(result).toEqual(mockResponse);
    });
  });

  describe('publishCollection', () => {
    it('should POST to publish collection endpoint with includeChildren', async () => {
      const mockResponse = {
        published: { type: 'Collection', id: 10, name: 'Test Collection' },
        promoted: [],
        childrenPublished: 25,
        requiresSlugSetup: true,
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockResponse,
      });

      const result = await publishApi.publishCollection(1, 10, true);

      const call = mockFetch.mock.calls[0];
      expect(call[0]).toBe('/api/workspaces/1/collections/10/publish');
      expect(call[1].method).toBe('POST');
      expect(JSON.parse(call[1].body)).toEqual({ includeChildren: true });
      expect(result).toEqual(mockResponse);
    });

    it('should POST with includeChildren false', async () => {
      const mockResponse = {
        published: { type: 'Collection', id: 10, name: 'Test Collection' },
        promoted: [],
        childrenPublished: 0,
        requiresSlugSetup: false,
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockResponse,
      });

      await publishApi.publishCollection(1, 10, false);

      const call = mockFetch.mock.calls[0];
      expect(JSON.parse(call[1].body)).toEqual({ includeChildren: false });
    });
  });

  describe('unpublishCollection', () => {
    it('should POST to unpublish collection endpoint', async () => {
      const mockResponse = {
        unpublished: { type: 'Collection', id: 10, name: 'Test Collection' },
        affectedPublicItems: 50,
        affectedPublicCategories: 5,
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockResponse,
      });

      const result = await publishApi.unpublishCollection(1, 10);

      const call = mockFetch.mock.calls[0];
      expect(call[0]).toBe('/api/workspaces/1/collections/10/unpublish');
      expect(call[1].method).toBe('POST');
      expect(result).toEqual(mockResponse);
    });
  });

  describe('unpublishCollectionPreview', () => {
    it('should GET unpublish collection preview', async () => {
      const mockResponse = {
        affectedPublicItems: 50,
        affectedPublicCategories: 5,
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockResponse,
      });

      const result = await publishApi.unpublishCollectionPreview(1, 10);

      const call = mockFetch.mock.calls[0];
      expect(call[0]).toBe('/api/workspaces/1/collections/10/unpublish-preview');
      expect(call[1].method).toBe('GET');
      expect(result).toEqual(mockResponse);
    });
  });

  describe('bulkPublish', () => {
    it('should POST to bulk publish endpoint with item IDs', async () => {
      const mockResponse = {
        publishedCount: 3,
        promoted: [{ type: 'Collection', id: 1, name: 'Test Collection' }],
        requiresSlugSetup: true,
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockResponse,
      });

      const result = await publishApi.bulkPublish(1, [10, 20, 30]);

      const call = mockFetch.mock.calls[0];
      expect(call[0]).toBe('/api/workspaces/1/items/bulk-publish');
      expect(call[1].method).toBe('POST');
      expect(JSON.parse(call[1].body)).toEqual({ itemIds: [10, 20, 30] });
      expect(result).toEqual(mockResponse);
    });
  });

  describe('bulkUnpublish', () => {
    it('should POST to bulk unpublish endpoint with item IDs', async () => {
      const mockResponse = {
        unpublishedCount: 2,
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockResponse,
      });

      const result = await publishApi.bulkUnpublish(1, [10, 20]);

      const call = mockFetch.mock.calls[0];
      expect(call[0]).toBe('/api/workspaces/1/items/bulk-unpublish');
      expect(call[1].method).toBe('POST');
      expect(JSON.parse(call[1].body)).toEqual({ itemIds: [10, 20] });
      expect(result).toEqual(mockResponse);
    });
  });
});
