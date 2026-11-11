import { afterEach, expect, it, vi } from 'vitest';
import { api } from '../../src/api/client';
import { templatesApi } from '../../src/api/templates';
import { categoriesApi } from '../../src/api/categories';

afterEach(() => vi.restoreAllMocks());

it('routes template reads through the shared transport and forwards cancellation', async () => {
  const get = vi.spyOn(api, 'get').mockResolvedValue([]);
  const options = { signal: new AbortController().signal };
  await templatesApi.getAll(undefined, options);
  expect(get).toHaveBeenLastCalledWith('/itemtemplates', options);
  await templatesApi.getAll('system', options);
  expect(get).toHaveBeenLastCalledWith('/itemtemplates?filter=system', options);
  await templatesApi.getAll('shared', options);
  expect(get).toHaveBeenLastCalledWith('/itemtemplates?filter=system', options);
  await templatesApi.getAll('workspace', options);
  expect(get).toHaveBeenLastCalledWith('/itemtemplates?filter=workspace', options);
  await templatesApi.getAll('personal', options);
  expect(get).toHaveBeenLastCalledWith('/itemtemplates?filter=workspace', options);
  await templatesApi.getById(3);
  expect(get).toHaveBeenLastCalledWith('/itemtemplates/3');
  await templatesApi.getForCollection(4, options);
  expect(get).toHaveBeenLastCalledWith('/collections/4/templates', options);
  await categoriesApi.getTemplates(5, options);
  expect(get).toHaveBeenLastCalledWith('/categories/5/templates', options);
});

it('routes template mutations and associations through the shared transport', async () => {
  const post = vi.spyOn(api, 'post').mockResolvedValue({ itemTemplateId: 3 });
  const put = vi.spyOn(api, 'put').mockResolvedValue({ itemTemplateId: 3 });
  const remove = vi.spyOn(api, 'delete').mockResolvedValue(undefined);
  const request = { name: 'Books', description: '', properties: [] };
  await expect(templatesApi.create(request)).resolves.toEqual({ itemTemplateId: 3 });
  expect(post).toHaveBeenLastCalledWith('/itemtemplates', request);
  await templatesApi.update(3, request);
  expect(put).toHaveBeenLastCalledWith('/itemtemplates/3', request);
  await templatesApi.delete(3);
  expect(remove).toHaveBeenLastCalledWith('/itemtemplates/3');
  await templatesApi.associateWithCollection(4, 3);
  expect(post).toHaveBeenLastCalledWith('/collections/4/templates/3');
  await templatesApi.disassociateFromCollection(4, 3);
  expect(remove).toHaveBeenLastCalledWith('/collections/4/templates/3');
});
