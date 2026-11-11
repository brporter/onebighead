import { useCollectionsData, useCategoriesData, useItemsData, useTemplatesData,
  useSuggestionsData, useThemesData, useImagesData } from '../../src/contexts/useData';

/** Aggregate observations for composition tests; production consumers use domain hooks. */
export function useData() {
  const collections = useCollectionsData();
  const categories = useCategoriesData();
  const items = useItemsData();
  const templates = useTemplatesData();
  const suggestions = useSuggestionsData();
  const themes = useThemesData();
  const images = useImagesData();
  return { ...collections, ...categories, ...items, ...templates, ...suggestions, ...themes, ...images };
}
