import { describe, it, expect } from 'vitest';
import items from '../../src/data/items';

describe('items data', () => {
  it('should export an array of items', () => {
    expect(Array.isArray(items)).toBe(true);
    expect(items.length).toBeGreaterThan(0);
  });

  it('should have valid item structure for each entry', () => {
    items.forEach((item) => {
      expect(item).toHaveProperty('id');
      expect(item).toHaveProperty('tenantId');
      expect(item).toHaveProperty('categoryId');
      expect(item).toHaveProperty('name');
      expect(item).toHaveProperty('summary');
      expect(item).toHaveProperty('description');
      expect(item).toHaveProperty('properties');
      expect(item).toHaveProperty('images');

      expect(typeof item.id).toBe('number');
      expect(typeof item.tenantId).toBe('number');
      expect(typeof item.categoryId).toBe('number');
      expect(typeof item.name).toBe('string');
      expect(typeof item.summary).toBe('string');
      expect(typeof item.description).toBe('string');
      expect(Array.isArray(item.properties)).toBe(true);
      expect(Array.isArray(item.images)).toBe(true);
    });
  });

  it('should have valid properties structure', () => {
    items.forEach((item) => {
      item.properties.forEach((prop) => {
        expect(prop).toHaveProperty('category');
        expect(prop).toHaveProperty('name');
        expect(prop).toHaveProperty('value');
        expect(typeof prop.category).toBe('string');
        expect(typeof prop.name).toBe('string');
        expect(typeof prop.value).toBe('string');
      });
    });
  });

  it('should have valid images structure', () => {
    items.forEach((item) => {
      item.images.forEach((image) => {
        expect(image).toHaveProperty('url');
        expect(image).toHaveProperty('alt');
        expect(typeof image.url).toBe('string');
        expect(typeof image.alt).toBe('string');
      });
    });
  });

  it('should have unique item ids', () => {
    const ids = items.map((i) => i.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });
});

