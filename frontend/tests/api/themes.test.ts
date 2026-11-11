import { afterEach, expect, it, vi } from 'vitest';
import { api } from '../../src/api/client';
import { themesApi } from '../../src/api/themes';
import { createMockCollectionTheme } from '../testUtils/factories';

afterEach(() => vi.restoreAllMocks());

it('loads the theme catalog and a selected theme through the shared transport', async () => {
  const theme = createMockCollectionTheme({ themeId: 8 });
  const get = vi.spyOn(api, 'get').mockResolvedValueOnce([theme]).mockResolvedValueOnce(theme);
  await expect(themesApi.getAll()).resolves.toEqual([theme]);
  expect(get).toHaveBeenLastCalledWith('/themes');
  await expect(themesApi.getById(8)).resolves.toBe(theme);
  expect(get).toHaveBeenLastCalledWith('/themes/8');
});

it('propagates catalog and theme errors for the owning UI to handle', async () => {
  const error = new Error('Theme unavailable');
  vi.spyOn(api, 'get').mockRejectedValue(error);
  await expect(themesApi.getAll()).rejects.toBe(error);
  await expect(themesApi.getById(8)).rejects.toBe(error);
});
