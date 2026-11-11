import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../../src/api/client';
import { publicApi } from '../../src/api/public';

afterEach(() => vi.restoreAllMocks());

describe('Public API adapter', () => {
  it('preserves request options across every public endpoint', async () => {
    const result = { id: 2 };
    const get = vi.spyOn(api, 'get').mockResolvedValue(result);
    const options = { signal: new AbortController().signal };

    await expect(publicApi.getWorkspace('library', options)).resolves.toBe(result);
    expect(get).toHaveBeenLastCalledWith('/public/library', options);
    await expect(publicApi.getCollections('library', options)).resolves.toBe(result);
    expect(get).toHaveBeenLastCalledWith('/public/library/collections', options);
    await expect(publicApi.getCollection('library', 2, options)).resolves.toBe(result);
    expect(get).toHaveBeenLastCalledWith('/public/library/collections/2', options);
    await expect(publicApi.getItems('library', 2, 5, options)).resolves.toBe(result);
    expect(get).toHaveBeenLastCalledWith('/public/library/collections/2/items?categoryId=5', options);
    await expect(publicApi.getItem('library', 3, options)).resolves.toBe(result);
    expect(get).toHaveBeenLastCalledWith('/public/library/items/3', options);
  });

  it('omits the category filter when browsing all items', async () => {
    const get = vi.spyOn(api, 'get').mockResolvedValue([]);
    await expect(publicApi.getItems('library', 2)).resolves.toEqual([]);
    expect(get).toHaveBeenCalledWith('/public/library/collections/2/items', undefined);
  });

  it('propagates errors to the owning request lifecycle', async () => {
    const error = new Error('No connection');
    vi.spyOn(api, 'get').mockRejectedValue(error);
    await expect(publicApi.getWorkspace('library')).rejects.toBe(error);
  });
});
