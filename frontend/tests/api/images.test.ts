import { expect, it, vi } from 'vitest';
import { api } from '../../src/api/client';
import { imagesApi } from '../../src/api/images';
vi.mock('../../src/api/client', () => ({ api: { upload: vi.fn(), delete: vi.fn() } }));
it('uploads multipart files with cancellation options and encodes image keys', async () => {
  const file = new File(['pixels'], 'image.png', { type: 'image/png' });
  const options = { signal: new AbortController().signal };
  await imagesApi.upload(file, options);
  const call = vi.mocked(api.upload).mock.calls[0];
  expect(call[0]).toBe('/images');
  expect(call[1].get('file')).toBe(file);
  expect(call[2]).toBe(options);
  await imagesApi.upload(file);
  expect(api.upload).toHaveBeenLastCalledWith('/images', expect.any(FormData), undefined);
  await imagesApi.delete('folder/key ?');
  expect(api.delete).toHaveBeenCalledWith('/images/folder%2Fkey%20%3F');
  expect(imagesApi.getUrl('folder/key ?')).toBe('/api/images/folder%2Fkey%20%3F');
});
