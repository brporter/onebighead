import { afterEach, expect, it, vi } from 'vitest';
import { saveDownload } from '../src/utils/saveDownload';

afterEach(() => vi.restoreAllMocks());

it.each([false, true])('releases browser download resources when click fails: %s', fail => {
  URL.createObjectURL = vi.fn().mockReturnValue('blob:download');
  URL.revokeObjectURL = vi.fn();
  const blob = new Blob(['backup']);
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
    expect(this.isConnected).toBe(true);
    expect(this.href).toBe('blob:download');
    expect(this.download).toBe('library.zip');
    if (fail) throw new Error('Download unavailable');
  });
  if (fail) expect(() => saveDownload({ blob, filename: 'library.zip' })).toThrow('Download unavailable');
  else saveDownload({ blob, filename: 'library.zip' });
  expect(URL.createObjectURL).toHaveBeenCalledWith(blob);
  expect(URL.revokeObjectURL).toHaveBeenCalledExactlyOnceWith('blob:download');
  expect(document.querySelector('a[download]')).toBeNull();
});
