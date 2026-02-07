import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { itemsApi } from '../../src/api/items';
import { createMockItem } from '../testUtils';

describe('itemsApi', () => {
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockFetch = vi.fn();
    vi.stubGlobal('fetch', mockFetch);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('getAll', () => {
    it('should fetch all items without options', async () => {
      const mockItems = [
        createMockItem({ id: 1, name: 'Item 1', categoryId: 1, effectiveIsPublic: true }),
      ];
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({ 'ETag': '"abc123"' }),
        json: async () => mockItems,
      });

      const result = await itemsApi.getAll();

      expect(mockFetch).toHaveBeenCalledWith('/api/items', expect.anything());
      expect(result.items).toEqual(mockItems);
      expect(result.etag).toBe('"abc123"');
      expect(result.notModified).toBe(false);
    });

    it('should include categoryId in query params', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => [],
      });

      await itemsApi.getAll({ categoryId: 5 });

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('categoryId=5'),
        expect.anything()
      );
    });

    it('should include includeDescendants in query params', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => [],
      });

      await itemsApi.getAll({ categoryId: 5, includeDescendants: true });

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('includeDescendants=true'),
        expect.anything()
      );
    });

    it('should send If-None-Match header when etag provided', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => [],
      });

      await itemsApi.getAll({ etag: '"prev-etag"' });

      const call = mockFetch.mock.calls[0];
      const headers = call[1].headers as Headers;
      expect(headers.get('If-None-Match')).toBe('"prev-etag"');
    });

    it('should return notModified=true for 304 response', async () => {
      // ApiClient returns undefined for 304
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 304,
      });

      const result = await itemsApi.getAll({ etag: '"abc"' });

      expect(result.notModified).toBe(true);
      expect(result.items).toEqual([]);
    });
  });

  describe('getById', () => {
    it('should fetch single item by id', async () => {
      const mockItem = createMockItem({
        id: 42,
        name: 'Test Item',
        summary: 'A test',
        description: 'Description',
        categoryId: 5,
        effectiveIsPublic: true,
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockItem,
      });

      const result = await itemsApi.getById(42);

      expect(mockFetch).toHaveBeenCalledWith('/api/items/42', expect.anything());
      expect(result).toEqual(mockItem);
    });
  });

  describe('create', () => {
    it('should POST new item', async () => {
      const newItem = createMockItem({
        id: null,
        name: 'New Item',
        properties: [{ category: 'Size', name: 'Width', value: '10cm' }],
        categoryId: 3,
        effectiveIsPublic: true,
      });

      const createdItem = { ...newItem, id: 99 };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 201,
        json: async () => createdItem,
      });

      const result = await itemsApi.create(newItem);

      const call = mockFetch.mock.calls[0];
      expect(call[1].method).toBe('POST');
      expect(JSON.parse(call[1].body)).toEqual(newItem);
      expect(result.id).toBe(99);
    });
  });

  describe('update', () => {
    it('should PUT updated item', async () => {
      const updatedItem = createMockItem({
        id: 42,
        name: 'Updated Name',
        summary: 'Updated summary',
        categoryId: 3,
        effectiveIsPublic: true,
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => updatedItem,
      });

      const result = await itemsApi.update(42, updatedItem);

      const call = mockFetch.mock.calls[0];
      expect(call[0]).toBe('/api/items/42');
      expect(call[1].method).toBe('PUT');
      expect(result.name).toBe('Updated Name');
    });
  });

  describe('delete', () => {
    it('should DELETE item', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 204,
      });

      await itemsApi.delete(42);

      const call = mockFetch.mock.calls[0];
      expect(call[0]).toBe('/api/items/42');
      expect(call[1].method).toBe('DELETE');
    });
  });
});
