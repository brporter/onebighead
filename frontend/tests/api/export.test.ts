import { afterEach, expect, it, vi } from 'vitest';
import { api } from '../../src/api/client';
import { exportApi } from '../../src/api/export';

afterEach(() => vi.restoreAllMocks());

it.each([
  [null, 'export.zip'],
  ['attachment; filename=onebighead-export.zip; filename*=UTF-8\'\'onebighead-export.zip', 'onebighead-export.zip'],
])('downloads the archive with its filename (%s)', async (header, filename) => {
  const response = new Response('archive', { headers: header ? { 'Content-Disposition': header } : {} });
  const body = vi.spyOn(response, 'blob');
  const download = vi.spyOn(api, 'download').mockResolvedValue(response);
  const result = await exportApi.downloadExport();
  expect(download).toHaveBeenCalledExactlyOnceWith('/export', { credentials: 'include' });
  expect(result.filename).toBe(filename);
  // Node's Response and jsdom's FileReader can use different Blob realms.
  // Verify that the download preserves the actual response body unchanged.
  expect(body).toHaveBeenCalledExactlyOnceWith();
  expect(result.blob).toBe(await body.mock.results[0].value);
  expect(result.blob.size).toBe('archive'.length);
});

it('propagates download and body read errors instead of producing an empty archive', async () => {
  const error = new Error('Download interrupted');
  const download = vi.spyOn(api, 'download').mockRejectedValueOnce(error);
  await expect(exportApi.downloadExport()).rejects.toBe(error);
  const response = new Response();
  vi.spyOn(response, 'blob').mockRejectedValueOnce(error);
  download.mockResolvedValue(response);
  await expect(exportApi.downloadExport()).rejects.toBe(error);
});
