import { StrictMode, createElement } from 'react';
import { act, renderHook } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { IMAGE_FILE_TYPES, IMAGE_SIZE_LIMIT_BYTES, imageDescription, validateImageFile } from '../../src/data/images/imageUploadPolicy';
import { useImageUploads, type ImageUploadPort } from '../../src/data/images/useImageUploads';
import { deferred } from '../testUtils/deferred';
const file = (name = 'photo.png') => new File(['pixels'], name, { type: 'image/png' });

it('accepts exactly the supported file types within the editor limit', () => {
  for (const type of IMAGE_FILE_TYPES) {
    expect(validateImageFile({ type, size: 1 })).toBeNull();
    expect(validateImageFile({ type, size: IMAGE_SIZE_LIMIT_BYTES })).toBeNull();
  }
  expect(validateImageFile({ type: 'image/png', size: IMAGE_SIZE_LIMIT_BYTES + 1 })).toContain('10 MB');
  expect(validateImageFile({ type: 'image/png', size: 0 })).toContain('empty');
  expect(validateImageFile({ type: 'text/plain', size: 1 })).toContain('Choose a JPEG');
  expect(imageDescription('front.view.png')).toBe('front.view');
  expect(imageDescription('no-extension')).toBe('no-extension');
  expect(imageDescription('.png')).toBe('Image');
});

it('validates files without invoking the upload port and keeps an empty selection inert', async () => {
  const upload = vi.fn<ImageUploadPort>();
  const added = vi.fn();
  const { result } = renderHook(() => useImageUploads(upload, added));
  await act(async () => { await result.current.select([]); });
  expect(result.current.pending).toBe(false);
  await act(async () => { await result.current.select([new File([], 'empty.png', { type: 'image/png' })]); });
  expect(upload).not.toHaveBeenCalled();
  expect(added).not.toHaveBeenCalled();
  expect(result.current.issues).toEqual([{ fileName: 'empty.png', message: 'This file is empty.' }]);
  expect(result.current.pending).toBe(false);
});

it('serializes a batch, rejects overlapping selection, and retains successes on both sides of a failure', async () => {
  const first = deferred<{ url: string }>();
  const upload = vi.fn<ImageUploadPort>().mockReturnValueOnce(first.promise).mockRejectedValueOnce(null).mockResolvedValueOnce({ url: '/third.png' });
  const added = vi.fn();
  const { result } = renderHook(() => useImageUploads(upload, added));
  let batch!: Promise<void>;
  act(() => { batch = result.current.select([file('first.png'), file('second.png'), file('third.png')]); });
  expect(result.current.pending).toBe(true);
  expect(upload).toHaveBeenCalledOnce();
  await act(async () => { await result.current.select([file('duplicate.png')]); });
  expect(upload).toHaveBeenCalledOnce();
  await act(async () => { first.resolve({ url: '/first.png' }); await batch; });
  expect(added).toHaveBeenCalledExactlyOnceWith([{ url: '/first.png', alt: 'first' }, { url: '/third.png', alt: 'third' }]);
  expect(result.current.issues).toEqual([{ fileName: 'second.png', message: 'Failed to upload image' }]);
  expect(result.current.completed).toBe(3);
  expect(result.current.pending).toBe(false);
  expect(upload.mock.calls.map(call => call[0].name)).toEqual(['first.png', 'second.png', 'third.png']);
});

it.each(['resolve', 'reject'] as const)('stops the batch and ignores late %s after unmount', async outcome => {
  const pending = deferred<{ url: string }>();
  const upload = vi.fn<ImageUploadPort>().mockReturnValue(pending.promise);
  const added = vi.fn();
  const { result, unmount } = renderHook(() => useImageUploads(upload, added));
  let batch!: Promise<void>;
  act(() => { batch = result.current.select([file('first.png'), file('later.png')]); });
  const signal = upload.mock.calls[0][1]?.signal;
  unmount();
  expect(signal?.aborted).toBe(true);
  await act(async () => {
    if (outcome === 'resolve') pending.resolve({ url: '/late.png' }); else pending.reject(new Error('Aborted'));
    await batch;
  });
  expect(added).not.toHaveBeenCalled();
  expect(upload).toHaveBeenCalledOnce();
});

it('allows uploads after StrictMode effect replay and clears previous errors on retry', async () => {
  const upload = vi.fn<ImageUploadPort>().mockRejectedValueOnce(new Error('Offline')).mockResolvedValue({ url: '/saved.png' });
  const added = vi.fn();
  const { result } = renderHook(() => useImageUploads(upload, added), { wrapper: ({ children }) => createElement(StrictMode, null, children) });
  await act(async () => { await result.current.select([file()]); });
  expect(result.current.issues).toHaveLength(1);
  await act(async () => { await result.current.select([file()]); });
  expect(result.current.issues).toEqual([]);
  expect(added).toHaveBeenCalledOnce();
});
