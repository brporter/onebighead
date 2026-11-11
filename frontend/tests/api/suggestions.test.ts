import { afterEach, expect, it, vi } from 'vitest';
import { api } from '../../src/api/client';
import { suggestionsApi } from '../../src/api/suggestions';

afterEach(() => vi.restoreAllMocks());

it('reads and rebuilds suggestions for the selected collection', async () => {
  const suggestions = { categories: ['Edition'], names: ['Publisher'] };
  const get = vi.spyOn(api, 'get').mockResolvedValue(suggestions);
  const post = vi.spyOn(api, 'post').mockResolvedValue(suggestions);
  await expect(suggestionsApi.get(42)).resolves.toBe(suggestions);
  expect(get).toHaveBeenCalledExactlyOnceWith('/collections/42/property-suggestions');
  await expect(suggestionsApi.sync(42)).resolves.toBe(suggestions);
  expect(post).toHaveBeenCalledExactlyOnceWith('/collections/42/property-suggestions/sync');
});

it('propagates suggestion errors to the owning collection workflow', async () => {
  const error = new Error('Collection unavailable');
  vi.spyOn(api, 'get').mockRejectedValue(error);
  vi.spyOn(api, 'post').mockRejectedValue(error);
  await expect(suggestionsApi.get(42)).rejects.toBe(error);
  await expect(suggestionsApi.sync(42)).rejects.toBe(error);
});
