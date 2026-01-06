import { describe, it, expect } from 'vitest';
import tenants from '../../src/data/tenants';

describe('tenants data', () => {
  it('should export an array of tenants', () => {
    expect(Array.isArray(tenants)).toBe(true);
    expect(tenants.length).toBeGreaterThan(0);
  });

  it('should have valid tenant structure for each entry', () => {
    tenants.forEach((tenant) => {
      expect(tenant).toHaveProperty('tenantId');
      expect(tenant).toHaveProperty('name');
      expect(tenant).toHaveProperty('owner');

      expect(typeof tenant.tenantId).toBe('number');
      expect(typeof tenant.name).toBe('string');
      expect(typeof tenant.owner).toBe('string');
    });
  });

  it('should have unique tenantIds', () => {
    const ids = tenants.map((t) => t.tenantId);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });

  it('should have valid email format for owner', () => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    tenants.forEach((tenant) => {
      expect(emailRegex.test(tenant.owner)).toBe(true);
    });
  });
});

