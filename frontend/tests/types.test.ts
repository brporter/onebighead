import { describe, it, expect } from 'vitest';
import type { Item, ItemProperty, ItemImage, Category, CategoryNode, Collection, Workspace } from '../src/utils/types';
import { Visibility, UserFlag } from '../src/utils/types';

describe('types', () => {
  describe('Item interface', () => {
    it('should accept valid Item object', () => {
      const item: Item = {
        id: 1,
        workspaceId: 1,
        collectionId: 1,
        categoryId: 1,
        templateKey: null,
        name: 'Test Item',
        summary: 'Test summary',
        description: 'Test description',
        properties: [],
        images: [],
        visibility: Visibility.Private,
        effectiveIsPublic: false,
        userFlag: UserFlag.Have,
      };

      expect(item.id).toBe(1);
      expect(item.name).toBe('Test Item');
    });

    it('should accept null id for new items', () => {
      const item: Item = {
        id: null,
        workspaceId: 1,
        collectionId: 1,
        categoryId: 1,
        templateKey: null,
        name: 'New Item',
        summary: '',
        description: '',
        properties: [],
        images: [],
        visibility: Visibility.Private,
        effectiveIsPublic: false,
        userFlag: UserFlag.Have,
      };

      expect(item.id).toBeNull();
    });

    it('should accept null categoryId', () => {
      const item: Item = {
        id: 1,
        workspaceId: 1,
        collectionId: 1,
        categoryId: null,
        templateKey: null,
        name: 'Uncategorized Item',
        summary: '',
        description: '',
        properties: [],
        images: [],
        visibility: Visibility.Private,
        effectiveIsPublic: false,
        userFlag: UserFlag.Have,
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
        workspaceId: 1,
        collectionId: 1,
        categoryId: 1,
        name: 'Test Category',
        description: 'Test description',
        parentCategoryId: null,
        isSystem: false,
        visibility: Visibility.Private,
        effectiveIsPublic: false,
        itemTemplateIds: [],
      };

      expect(category.categoryId).toBe(1);
      expect(category.parentCategoryId).toBeNull();
    });

    it('should accept parentCategoryId as number', () => {
      const category: Category = {
        workspaceId: 1,
        collectionId: 1,
        categoryId: 2,
        name: 'Child Category',
        description: 'Child description',
        parentCategoryId: 1,
        isSystem: false,
        visibility: Visibility.Private,
        effectiveIsPublic: false,
        itemTemplateIds: [],
      };

      expect(category.parentCategoryId).toBe(1);
    });
  });

  describe('CategoryNode interface', () => {
    it('should extend Category with children array', () => {
      const node: CategoryNode = {
        workspaceId: 1,
        collectionId: 1,
        categoryId: 1,
        name: 'Parent',
        description: 'Parent desc',
        parentCategoryId: null,
        isSystem: false,
        visibility: Visibility.Private,
        effectiveIsPublic: false,
        itemTemplateIds: [],
        children: [
          {
            workspaceId: 1,
            collectionId: 1,
            categoryId: 2,
            name: 'Child',
            description: 'Child desc',
            parentCategoryId: 1,
            isSystem: false,
            visibility: Visibility.Private,
            effectiveIsPublic: false,
            itemTemplateIds: [],
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
        workspaceId: 1,
        name: 'My Collection',
        description: 'Test description',
        heroImageUrl: null,
        slug: 'my-collection',
        visibility: Visibility.Private,
        effectiveIsPublic: false,
      };

      expect(collection.collectionId).toBe(1);
      expect(collection.name).toBe('My Collection');
    });
  });

  describe('Workspace interface', () => {
    it('should accept valid Workspace object', () => {
      const workspace: Workspace = {
        workspaceId: 1,
        name: 'Test Workspace',
        owner: 'owner@example.com',
      };

      expect(workspace.workspaceId).toBe(1);
      expect(workspace.owner).toBe('owner@example.com');
    });
  });
});
