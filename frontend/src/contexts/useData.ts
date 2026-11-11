import { useContext, type Context } from 'react';
import { CollectionsContext, CategoriesContext, ItemsContext, TemplatesContext,
  SuggestionsContext, ThemesContext, ImagesContext } from './dataContexts';

function useDomain<T>(context: Context<T | null>): T {
  const value = useContext(context);
  if (value === null) throw new Error('Data hooks must be used within a DataProvider');
  return value;
}

export function useCollectionsData() { return useDomain(CollectionsContext); }
export function useCategoriesData() { return useDomain(CategoriesContext); }
export function useItemsData() { return useDomain(ItemsContext); }
export function useTemplatesData() { return useDomain(TemplatesContext); }
export function useSuggestionsData() { return useDomain(SuggestionsContext); }
export function useThemesData() { return useDomain(ThemesContext); }
export function useImagesData() { return useDomain(ImagesContext); }
