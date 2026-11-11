import { describe, expect, it } from 'vitest';
import { parseRouteId } from '../src/utils/routeIds';

describe('parseRouteId', () => {
  it.each([undefined, '', '0', '-1', '1.2', '1book', '1e2', ' 1', '1 ', '2147483648', '99999999999999999999'])('rejects %s', value => {
    expect(parseRouteId(value)).toBeNull();
  });
  it.each(['1', '001', '2147483647'])('accepts %s', value => {
    expect(parseRouteId(value)).toBe(Number(value));
  });
});
