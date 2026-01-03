import { describe, it, expect } from 'vitest';
import collections from '../../src/data/collections';

describe('collections data', () => {
  it('should export an array of collections', () => {
    expect(Array.isArray(collections)).toBe(true);
    expect(collections.length).toBeGreaterThan(0);
  });

  it('should have valid collection structure for each entry', () => {
    collections.forEach((collection) => {
      expect(collection).toHaveProperty('collectionId');
      expect(collection).toHaveProperty('name');
      expect(collection).toHaveProperty('tenantId');

      expect(typeof collection.collectionId).toBe('number');
      expect(typeof collection.name).toBe('string');
      expect(typeof collection.tenantId).toBe('number');
    });
  });

  it('should have unique collectionIds', () => {
    const ids = collections.map((c) => c.collectionId);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });
});

