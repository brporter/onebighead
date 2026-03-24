import { describe, it, expect } from 'vitest';
import { getAccentColor, DEFAULT_PALETTE } from '../src/utils/accentColors';

describe('getAccentColor', () => {
  it('should return first palette color for index 0', () => {
    const color = getAccentColor(0);
    expect(color).toEqual(DEFAULT_PALETTE[0]);
  });

  it('should return second palette color for index 1', () => {
    const color = getAccentColor(1);
    expect(color).toEqual(DEFAULT_PALETTE[1]);
  });

  it('should cycle through palette when index exceeds palette length', () => {
    const color = getAccentColor(DEFAULT_PALETTE.length);
    expect(color).toEqual(DEFAULT_PALETTE[0]);
  });

  it('should cycle correctly for large indices', () => {
    const color = getAccentColor(DEFAULT_PALETTE.length + 3);
    expect(color).toEqual(DEFAULT_PALETTE[3]);
  });

  it('should handle index 0 with custom palette', () => {
    const custom = [{ start: '#aaa', end: '#bbb', name: 'Test' }];
    const color = getAccentColor(0, custom);
    expect(color).toEqual(custom[0]);
  });

  it('should return gradient CSS string from color', () => {
    const color = getAccentColor(0);
    expect(color.start).toBe('#c77d4a');
    expect(color.end).toBe('#d4a574');
    expect(color.name).toBe('Warm copper');
  });
});

describe('DEFAULT_PALETTE', () => {
  it('should have 8 colors', () => {
    expect(DEFAULT_PALETTE).toHaveLength(8);
  });

  it('should have start, end, and name for each color', () => {
    for (const color of DEFAULT_PALETTE) {
      expect(color).toHaveProperty('start');
      expect(color).toHaveProperty('end');
      expect(color).toHaveProperty('name');
      expect(color.start).toMatch(/^#[0-9a-f]{6}$/);
      expect(color.end).toMatch(/^#[0-9a-f]{6}$/);
    }
  });
});
