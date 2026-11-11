import type { CollectionsData, CategoriesData, ItemsData, TemplatesData,
  SuggestionsData, ThemesData, ImagesData } from '../../src/contexts/dataContexts';

/** Combined fixtures belong to tests; application components select domain ports. */
export type DataContextValue = CollectionsData & CategoriesData & ItemsData & TemplatesData
  & SuggestionsData & ThemesData & ImagesData;
