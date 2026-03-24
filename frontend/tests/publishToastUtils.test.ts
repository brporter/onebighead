import { describe, it, expect } from 'vitest';
import {
  buildPublishToastMessage,
  buildPublishToastDetails,
  buildBulkPublishToastMessage,
  buildBulkPublishToastDetails,
  buildUnpublishToastMessage,
  buildBulkUnpublishToastMessage,
} from '../src/utils/publishToastUtils';
import type {
  PublishResponse,
  BulkPublishResponse,
  UnpublishResponse,
  BulkUnpublishResponse,
} from '../src/utils/types';

describe('publishToastUtils', () => {
  describe('buildPublishToastMessage', () => {
    it('should return entity name with published suffix', () => {
      const response: PublishResponse = {
        published: { type: 'Item', id: 1, name: 'Omega Speedmaster' },
        promoted: [],
        childrenPublished: 0,
        requiresSlugSetup: false,
      };

      expect(buildPublishToastMessage(response)).toBe('Omega Speedmaster published.');
    });
  });

  describe('buildPublishToastDetails', () => {
    it('should return undefined when no promoted entities', () => {
      const response: PublishResponse = {
        published: { type: 'Item', id: 1, name: 'Test Item' },
        promoted: [],
        childrenPublished: 0,
        requiresSlugSetup: false,
      };

      expect(buildPublishToastDetails(response)).toBeUndefined();
    });

    it('should return single promoted entity message', () => {
      const response: PublishResponse = {
        published: { type: 'Item', id: 1, name: 'Omega Speedmaster' },
        promoted: [{ type: 'Category', id: 2, name: 'Vintage Watches' }],
        childrenPublished: 0,
        requiresSlugSetup: false,
      };

      expect(buildPublishToastDetails(response)).toBe(
        "Category 'Vintage Watches' is now visible in your gallery."
      );
    });

    it('should return multiple promoted entities message', () => {
      const response: PublishResponse = {
        published: { type: 'Item', id: 1, name: 'Test' },
        promoted: [
          { type: 'Category', id: 2, name: 'Watches' },
          { type: 'Collection', id: 3, name: 'My Collection' },
        ],
        childrenPublished: 0,
        requiresSlugSetup: false,
      };

      expect(buildPublishToastDetails(response)).toBe(
        "Promoted: 'Watches', 'My Collection' are now visible in your gallery."
      );
    });
  });

  describe('buildBulkPublishToastMessage', () => {
    it('should use singular for single item', () => {
      const response: BulkPublishResponse = {
        publishedCount: 1,
        promoted: [],
        requiresSlugSetup: false,
      };

      expect(buildBulkPublishToastMessage(response)).toBe('1 item published.');
    });

    it('should use plural for multiple items', () => {
      const response: BulkPublishResponse = {
        publishedCount: 5,
        promoted: [],
        requiresSlugSetup: false,
      };

      expect(buildBulkPublishToastMessage(response)).toBe('5 items published.');
    });
  });

  describe('buildBulkPublishToastDetails', () => {
    it('should return undefined when no promoted entities', () => {
      const response: BulkPublishResponse = {
        publishedCount: 3,
        promoted: [],
        requiresSlugSetup: false,
      };

      expect(buildBulkPublishToastDetails(response)).toBeUndefined();
    });

    it('should return promoted entities message', () => {
      const response: BulkPublishResponse = {
        publishedCount: 3,
        promoted: [{ type: 'Category', id: 1, name: 'Watches' }],
        requiresSlugSetup: false,
      };

      expect(buildBulkPublishToastDetails(response)).toBe(
        "Promoted: 'Watches' are now visible in your gallery."
      );
    });
  });

  describe('buildUnpublishToastMessage', () => {
    it('should return entity name with unpublished suffix', () => {
      const response: UnpublishResponse = {
        unpublished: { type: 'Item', id: 1, name: 'Omega Speedmaster' },
        affectedPublicItems: 0,
        affectedPublicCategories: 0,
      };

      expect(buildUnpublishToastMessage(response)).toBe('Omega Speedmaster unpublished.');
    });
  });

  describe('buildBulkUnpublishToastMessage', () => {
    it('should use singular for single item', () => {
      const response: BulkUnpublishResponse = { unpublishedCount: 1 };

      expect(buildBulkUnpublishToastMessage(response)).toBe('1 item unpublished.');
    });

    it('should use plural for multiple items', () => {
      const response: BulkUnpublishResponse = { unpublishedCount: 3 };

      expect(buildBulkUnpublishToastMessage(response)).toBe('3 items unpublished.');
    });
  });
});
