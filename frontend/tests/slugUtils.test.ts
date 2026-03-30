import { describe, it, expect } from 'vitest';
import { toSlug, isValidSlug } from '../src/utils/slugUtils';

describe('toSlug', () => {
  it('should convert a name to lowercase', () => {
    expect(toSlug('Hello World')).toBe('hello-world');
  });

  it('should replace non-alphanumeric characters with hyphens', () => {
    expect(toSlug('My Cool Collection!')).toBe('my-cool-collection');
  });

  it('should collapse multiple hyphens', () => {
    expect(toSlug('hello---world')).toBe('hello-world');
  });

  it('should remove leading and trailing hyphens', () => {
    expect(toSlug('-hello-world-')).toBe('hello-world');
  });

  it('should truncate to 50 characters', () => {
    const longName = 'a'.repeat(60);
    expect(toSlug(longName)).toHaveLength(50);
  });

  it('should handle empty string', () => {
    expect(toSlug('')).toBe('');
  });

  it('should handle string with only special characters', () => {
    expect(toSlug('!!!')).toBe('');
  });
});

describe('isValidSlug', () => {
  it('should accept a valid slug', () => {
    expect(isValidSlug('my-watches')).toBe(true);
  });

  it('should accept alphanumeric only slug', () => {
    expect(isValidSlug('watches123')).toBe(true);
  });

  it('should reject slugs shorter than 3 characters', () => {
    expect(isValidSlug('ab')).toBe(false);
  });

  it('should accept slugs of exactly 3 characters', () => {
    expect(isValidSlug('abc')).toBe(true);
  });

  it('should reject slugs longer than 50 characters', () => {
    expect(isValidSlug('a'.repeat(51))).toBe(false);
  });

  it('should accept slugs of exactly 50 characters', () => {
    expect(isValidSlug('a'.repeat(50))).toBe(true);
  });

  it('should reject slugs with leading hyphens', () => {
    expect(isValidSlug('-my-watches')).toBe(false);
  });

  it('should reject slugs with trailing hyphens', () => {
    expect(isValidSlug('my-watches-')).toBe(false);
  });

  it('should reject slugs with consecutive hyphens', () => {
    expect(isValidSlug('my--watches')).toBe(false);
  });

  it('should reject slugs with uppercase letters', () => {
    expect(isValidSlug('My-Watches')).toBe(false);
  });

  it('should reject slugs with special characters', () => {
    expect(isValidSlug('my_watches')).toBe(false);
  });

  it('should reject empty string', () => {
    expect(isValidSlug('')).toBe(false);
  });
});
