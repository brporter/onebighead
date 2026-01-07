import { describe, it, expect } from 'vitest';
import type { Item, ItemProperty, ItemImage, Category, CategoryNode, Collection, Tenant } from '../src/types';

describe('types', () => {
  describe('Item interface', () => {
    it('should accept valid Item object', () => {
      const item: Item = {
        id: 1,
        tenantId: 1,
        categoryId: 1,
        name: 'Test Item',
        summary: 'Test summary',
        description: 'Test description',
        properties: [],
        images: [],
      };

      expect(item.id).toBe(1);
      expect(item.name).toBe('Test Item');
    });

    it('should accept null id for new items', () => {
      const item: Item = {
        id: null,
        tenantId: 1,
        categoryId: 1,
        name: 'New Item',
        summary: '',
        description: '',
        properties: [],
        images: [],
      };

      expect(item.id).toBeNull();
    });

    it('should accept null categoryId', () => {
      const item: Item = {
        id: 1,
        tenantId: 1,
        categoryId: null,
        name: 'Uncategorized Item',
        summary: '',
        description: '',
        properties: [],
        images: [],
      };

      expect(item.categoryId).toBeNull();
    });
  });

  describe('ItemProperty interface', () => {
    it('should accept valid ItemProperty object', () => {
      const property: ItemProperty = {
        category: 'General',
        name: 'Color',
        value: 'Blue',
      };

      expect(property.category).toBe('General');
      expect(property.name).toBe('Color');
      expect(property.value).toBe('Blue');
    });
  });

  describe('ItemImage interface', () => {
    it('should accept valid ItemImage object', () => {
      const image: ItemImage = {
        url: 'https://example.com/image.jpg',
        alt: 'Example image',
      };

      expect(image.url).toBe('https://example.com/image.jpg');
      expect(image.alt).toBe('Example image');
    });
  });

  describe('Category interface', () => {
    it('should accept valid Category object', () => {
      const category: Category = {
        tenantId: 1,
        categoryId: 1,
        name: 'Test Category',
        description: 'Test description',
        parentCategoryId: null,
        isSystem: false,
      };

      expect(category.categoryId).toBe(1);
      expect(category.parentCategoryId).toBeNull();
    });

    it('should accept parentCategoryId as number', () => {
      const category: Category = {
        tenantId: 1,
        categoryId: 2,
        name: 'Child Category',
        description: 'Child description',
        parentCategoryId: 1,
        isSystem: false,
      };

      expect(category.parentCategoryId).toBe(1);
    });
  });

  describe('CategoryNode interface', () => {
    it('should extend Category with children array', () => {
      const node: CategoryNode = {
        tenantId: 1,
        categoryId: 1,
        name: 'Parent',
        description: 'Parent desc',
        parentCategoryId: null,
        isSystem: false,
        children: [
          {
            tenantId: 1,
            categoryId: 2,
            name: 'Child',
            description: 'Child desc',
            parentCategoryId: 1,
            isSystem: false,
            children: [],
          },
        ],
      };

      expect(node.children.length).toBe(1);
      expect(node.children[0].name).toBe('Child');
    });
  });

  describe('Collection interface', () => {
    it('should accept valid Collection object', () => {
      const collection: Collection = {
        collectionId: 1,
        name: 'My Collection',
        tenantId: 1,
      };

      expect(collection.collectionId).toBe(1);
      expect(collection.name).toBe('My Collection');
    });
  });

  describe('Tenant interface', () => {
    it('should accept valid Tenant object', () => {
      const tenant: Tenant = {
        tenantId: 1,
        name: 'Test Tenant',
        owner: 'owner@example.com',
      };

      expect(tenant.tenantId).toBe(1);
      expect(tenant.owner).toBe('owner@example.com');
    });
  });
});

