import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { categoriesApi } from '../../src/api/categories';
import type { Category } from '../../src/utils/types';
import { Visibility } from '../../src/utils/types';

describe('categoriesApi', () => {
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockFetch = vi.fn();
    vi.stubGlobal('fetch', mockFetch);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('getAll', () => {
    it('should fetch all categories without collectionId', async () => {
      const mockCategories: Category[] = [
        { workspaceId: 1, collectionId: 1, categoryId: 1, name: 'Cat 1', description: '', parentCategoryId: null, isSystem: false, visibility: Visibility.Private, effectiveIsPublic: false, itemTemplateIds: [], sortOrder: 0 },
      ];

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockCategories,
      });

      const result = await categoriesApi.getAll();

      expect(mockFetch).toHaveBeenCalledWith('/api/categories', expect.anything());
      expect(result).toEqual(mockCategories);
    });

    it('should include collectionId in query params', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => [],
      });

      await categoriesApi.getAll(5);

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('collectionId=5'),
        expect.anything()
      );
    });
  });

  describe('getById', () => {
    it('should fetch single category by id', async () => {
      const mockCategory: Category = {
        workspaceId: 1, collectionId: 1, categoryId: 42, name: 'Test', description: '', parentCategoryId: null, isSystem: false, visibility: Visibility.Private, effectiveIsPublic: false, itemTemplateIds: [], sortOrder: 0,
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockCategory,
      });

      const result = await categoriesApi.getById(42);

      expect(mockFetch).toHaveBeenCalledWith('/api/categories/42', expect.anything());
      expect(result).toEqual(mockCategory);
    });
  });

  describe('create', () => {
    it('should POST new category', async () => {
      const created: Category = {
        workspaceId: 1, collectionId: 1, categoryId: 99, name: 'New', description: 'Desc', parentCategoryId: null, isSystem: false, visibility: Visibility.Private, effectiveIsPublic: false, itemTemplateIds: [], sortOrder: 0,
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 201,
        json: async () => created,
      });

      const result = await categoriesApi.create({ collectionId: 1, name: 'New', description: 'Desc' });

      const call = mockFetch.mock.calls[0];
      expect(call[1].method).toBe('POST');
      expect(result.categoryId).toBe(99);
    });
  });

  describe('update', () => {
    it('should PUT updated category', async () => {
      const updated: Category = {
        workspaceId: 1, collectionId: 1, categoryId: 1, name: 'Updated', description: '', parentCategoryId: null, isSystem: false, visibility: Visibility.Private, effectiveIsPublic: false, itemTemplateIds: [], sortOrder: 0,
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => updated,
      });

      const result = await categoriesApi.update(1, { name: 'Updated' });

      const call = mockFetch.mock.calls[0];
      expect(call[0]).toBe('/api/categories/1');
      expect(call[1].method).toBe('PUT');
      expect(result.name).toBe('Updated');
    });
  });

  describe('delete', () => {
    it('should DELETE category', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 204,
      });

      await categoriesApi.delete(42);

      const call = mockFetch.mock.calls[0];
      expect(call[0]).toBe('/api/categories/42');
      expect(call[1].method).toBe('DELETE');
    });
  });

  describe('reorder', () => {
    it('should PUT reorder request and return updated categories', async () => {
      const reordered: Category[] = [
        { workspaceId: 1, collectionId: 1, categoryId: 1, name: 'Cat 1', description: '', parentCategoryId: null, isSystem: false, visibility: Visibility.Private, effectiveIsPublic: false, itemTemplateIds: [], sortOrder: 1 },
        { workspaceId: 1, collectionId: 1, categoryId: 2, name: 'Cat 2', description: '', parentCategoryId: null, isSystem: false, visibility: Visibility.Private, effectiveIsPublic: false, itemTemplateIds: [], sortOrder: 0 },
      ];

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => reordered,
      });

      const result = await categoriesApi.reorder({
        categories: [
          { categoryId: 1, sortOrder: 1 },
          { categoryId: 2, sortOrder: 0 },
        ],
      });

      const call = mockFetch.mock.calls[0];
      expect(call[0]).toBe('/api/categories/reorder');
      expect(call[1].method).toBe('PUT');
      expect(JSON.parse(call[1].body)).toEqual({
        categories: [
          { categoryId: 1, sortOrder: 1 },
          { categoryId: 2, sortOrder: 0 },
        ],
      });
      expect(result).toEqual(reordered);
      expect(result[0].sortOrder).toBe(1);
      expect(result[1].sortOrder).toBe(0);
    });
  });

  describe('getTemplates', () => {
    it('should fetch templates for a category', async () => {
      const templateIds = [1, 2, 3];

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => templateIds,
      });

      const result = await categoriesApi.getTemplates(5);

      expect(mockFetch).toHaveBeenCalledWith('/api/categories/5/templates', expect.anything());
      expect(result).toEqual(templateIds);
    });
  });
});
