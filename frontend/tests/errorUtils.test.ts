import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../src/api/transport';
import { getErrorMessage, logError } from '../src/utils/errorUtils';

afterEach(() => vi.restoreAllMocks());

describe('Shared error formatting', () => {
  it.each([
    [new ApiError('Not found', 404, 'Not Found'), 'Not found (404)'],
    [new ApiError('Offline', 0, 'NetworkError'), 'Offline'],
    [new Error('Invalid input'), 'Invalid input'],
    [null, 'Unable to load'],
  ])('formats %s for display', (error, expected) => {
    expect(getErrorMessage(error, 'Unable to load')).toBe(expected);
  });

  it('logs HTTP context with its status', () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    logError('Loading items', new ApiError('Not found', 404, 'Not Found'));
    expect(log).toHaveBeenCalledWith('Loading items: Not found (status: 404)');
  });

  it('preserves unknown errors for diagnostics', () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    const error = { message: 'Unexpected response' };
    logError('Loading items', error);
    expect(log).toHaveBeenCalledWith('Loading items:', error);
  });
});
