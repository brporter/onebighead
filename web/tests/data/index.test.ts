import { describe, it, expect } from 'vitest';
import { categories, items, collections, tenants } from '../../src/data';

describe('data barrel export', () => {
  it('should export categories', () => {
    expect(categories).toBeDefined();
    expect(Array.isArray(categories)).toBe(true);
  });

  it('should export items', () => {
    expect(items).toBeDefined();
    expect(Array.isArray(items)).toBe(true);
  });

  it('should export collections', () => {
    expect(collections).toBeDefined();
    expect(Array.isArray(collections)).toBe(true);
  });

  it('should export tenants', () => {
    expect(tenants).toBeDefined();
    expect(Array.isArray(tenants)).toBe(true);
  });
});

