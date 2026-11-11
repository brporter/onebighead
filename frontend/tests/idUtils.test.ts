import { expect, it } from 'vitest';
import { generateUniqueId } from '../src/utils/idUtils';

it('generates unique IDs with default or caller supplied prefixes', () => {
  const first = generateUniqueId();
  const second = generateUniqueId();
  expect(first).toMatch(/^id-[0-9a-f-]{36}$/);
  expect(first).not.toBe(second);
  expect(generateUniqueId('property')).toMatch(/^property-[0-9a-f-]{36}$/);
});
