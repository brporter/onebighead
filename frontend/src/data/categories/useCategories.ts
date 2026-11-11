import { useMemo, useCallback, useEffect, useRef } from 'react';
import type { Category } from '../../utils/types';
import type { CreateCategoryRequest, UpdateCategoryRequest, ReorderCategoriesRequest } from '../../api/categories';
import type { CategoryGateway } from '../contracts';
import type { RequestOptions } from '../../api/transport';
import { useAsyncResource, type ResourceLoadOptions } from '../shared/useAsyncResource';
import { upsertBy } from '../shared/upsertBy';

export function useCategories(gateway: CategoryGateway, invalidateItems: () => void) {
  const { data: categories, setData, mutate, loading: categoriesLoading, error: categoriesError, load } =
    useAsyncResource<Category[]>([], 'Failed to fetch categories');
  const scope = useRef({ collectionId: null as number | null, epoch: 0, mounted: true });
  useEffect(() => {
    const current = scope.current;
    current.mounted = true;
    return () => { current.mounted = false; current.epoch++; };
  }, []);
  const capture = useCallback(() => {
    const epoch = scope.current.epoch;
    return (collectionId?: number) => scope.current.mounted && epoch === scope.current.epoch &&
      (collectionId === undefined || scope.current.collectionId === null || collectionId === scope.current.collectionId);
  }, []);

  const loadCategoriesForCollection = useCallback((id: number, options?: ResourceLoadOptions) => {
    if (scope.current.collectionId !== id) {
      if (scope.current.collectionId !== null) scope.current.epoch++;
      scope.current.collectionId = id;
      setData([]);
    }
    return load(() => gateway.getAll(id, options), options);
  }, [gateway, load, setData]);
  const addCategory = useCallback(async (request: CreateCategoryRequest) => {
    const accepts = capture();
    const created = await gateway.create(request);
    if (accepts(created.collectionId)) mutate(previous => upsertBy(previous, created, 'categoryId'));
    return created.categoryId;
  }, [gateway, mutate, capture]);
  const updateCategory = useCallback(async (id: number, request: UpdateCategoryRequest) => {
    const accepts = capture();
    const updated = await gateway.update(id, request);
    if (accepts(updated.collectionId)) mutate(previous => upsertBy(previous, updated, 'categoryId'));
    if (scope.current.mounted) invalidateItems();
  }, [gateway, mutate, capture, invalidateItems]);
  const deleteCategory = useCallback(async (id: number) => {
    const accepts = capture();
    await gateway.delete(id);
    if (accepts()) mutate(previous => previous.filter(category => category.categoryId !== id));
    if (scope.current.mounted) invalidateItems();
  }, [gateway, mutate, capture, invalidateItems]);
  const getCategoryTemplates = useCallback((id: number, options?: RequestOptions) => gateway.getTemplates(id, options), [gateway]);
  const reorderCategories = useCallback(async (updates: ReorderCategoriesRequest['categories']) => {
    const accepts = capture();
    const ordered = await gateway.reorder({ categories: updates });
    if (accepts() && ordered.every(category => accepts(category.collectionId))) mutate(() => ordered);
  }, [gateway, mutate, capture]);

  return useMemo(() => ({ categories, categoriesLoading, categoriesError, loadCategoriesForCollection, addCategory,
    updateCategory, deleteCategory, getCategoryTemplates, reorderCategories }), [categories, categoriesLoading, categoriesError, loadCategoriesForCollection, addCategory, updateCategory, deleteCategory, getCategoryTemplates, reorderCategories]);
}
