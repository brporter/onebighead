import { expect, it, vi } from 'vitest';
import { api } from '../../src/api/client';
import { dashboardApi } from '../../src/api/dashboard';

vi.mock('../../src/api/client', () => ({ api: { get: vi.fn() } }));

it('forwards dashboard reads and cancellation to the shared API client', async () => {
  const response = { collectionCount: 0, itemCount: 0, imageCount: 0, imageTotalSizeBytes: 0, dailyViews: [] };
  vi.mocked(api.get).mockResolvedValue(response);
  expect(await dashboardApi.get()).toBe(response);
  expect(api.get).toHaveBeenLastCalledWith('/dashboard', undefined);
  const options = { signal: new AbortController().signal };
  expect(await dashboardApi.get(options)).toBe(response);
  expect(api.get).toHaveBeenLastCalledWith('/dashboard', options);
});
