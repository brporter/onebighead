import { afterEach, expect, it, vi } from 'vitest';
import { api } from '../../src/api/client';
import { bulkUpdatesApi } from '../../src/api/bulkUpdates';

afterEach(() => vi.restoreAllMocks());

it('uses the shared transport for preview, enqueue and cancellable status queries', async () => {
  const post = vi.spyOn(api, 'post').mockResolvedValue({ jobId: 'one' });
  const get = vi.spyOn(api, 'get').mockResolvedValue(null);
  const preview = { scope: 'Collection', collectionId: 1 };
  const options = { signal: new AbortController().signal };
  await bulkUpdatesApi.preview(preview, options);
  expect(post).toHaveBeenLastCalledWith('/bulkupdates/preview', preview, options);
  const request = { ...preview, oldProperties: [], newProperties: [] };
  await expect(bulkUpdatesApi.enqueue(request, options)).resolves.toEqual({ jobId: 'one' });
  expect(post).toHaveBeenLastCalledWith('/bulkupdates', request, options);
  await bulkUpdatesApi.getStatus('one', options);
  expect(get).toHaveBeenLastCalledWith('/bulkupdates/one', options);
  await expect(bulkUpdatesApi.getCollectionStatus(1, options)).resolves.toBeNull();
  expect(get).toHaveBeenLastCalledWith('/bulkupdates/collection/1/status', options);
});
