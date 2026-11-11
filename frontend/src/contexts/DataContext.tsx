import { type ReactNode } from 'react';
import { collectionsApi, categoriesApi, itemsApi, imagesApi, templatesApi, suggestionsApi, themesApi } from '../api';
import { useCollections } from '../data/collections/useCollections';
import { useCategories } from '../data/categories/useCategories';
import { useItems } from '../data/items/useItems';
import { useTemplates } from '../data/templates/useTemplates';
import { useSuggestions } from '../data/suggestions/useSuggestions';
import { useThemes } from '../data/themes/useThemes';
import { CollectionsContext, CategoriesContext, ItemsContext, TemplatesContext,
  SuggestionsContext, ThemesContext, ImagesContext } from './dataContexts';

const images = { uploadImage: imagesApi.upload };

/** Composition root: HTTP adapters are connected to independently testable state modules here. */
export function DataProvider({ children }: { children: ReactNode }) {
  const collections = useCollections(collectionsApi);
  const suggestions = useSuggestions(suggestionsApi);
  const items = useItems(itemsApi, suggestions.syncPropertySuggestions);
  const categories = useCategories(categoriesApi, items.invalidateItemCache);
  const templates = useTemplates(templatesApi);
  const themes = useThemes(themesApi);

  return <CollectionsContext.Provider value={collections}>
    <CategoriesContext.Provider value={categories}>
      <ItemsContext.Provider value={items}>
        <TemplatesContext.Provider value={templates}>
          <SuggestionsContext.Provider value={suggestions}>
            <ThemesContext.Provider value={themes}>
              <ImagesContext.Provider value={images}>{children}</ImagesContext.Provider>
            </ThemesContext.Provider>
          </SuggestionsContext.Provider>
        </TemplatesContext.Provider>
      </ItemsContext.Provider>
    </CategoriesContext.Provider>
  </CollectionsContext.Provider>;
}
