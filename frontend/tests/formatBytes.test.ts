import { expect, it } from 'vitest';
import { formatBytes } from '../src/utils/formatBytes';

it.each([
  [0, '0 B'], [-1, '0 B'], [NaN, '0 B'], [Infinity, '0 B'],
  [0.5, '1 B'], [1, '1 B'], [1023, '1023 B'], [1024, '1.0 KB'],
  [1536, '1.5 KB'], [1024 ** 2, '1.0 MB'], [1024 ** 3, '1.0 GB'],
  [1024 ** 4, '1.0 TB'], [1024 ** 5, '1.0 PB'], [1024 ** 6, '1.0 EB'],
  [1024 ** 7, '1024.0 EB'],
])('formats %s bytes as %s', (bytes, expected) => expect(formatBytes(bytes)).toBe(expected));
