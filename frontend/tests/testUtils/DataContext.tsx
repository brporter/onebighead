import type { ReactNode } from 'react';
import type { DataContextValue } from './dataTypes';
import { CollectionsContext, CategoriesContext, ItemsContext, TemplatesContext,
  SuggestionsContext, ThemesContext, ImagesContext } from '../../src/contexts/dataContexts';

/** Component tests can assemble domain fixtures without starting HTTP-backed state. */
export default function DataContext({ value, children }: { value: DataContextValue; children: ReactNode }) {
  return <CollectionsContext.Provider value={value}>
    <CategoriesContext.Provider value={value}>
      <ItemsContext.Provider value={value}>
        <TemplatesContext.Provider value={value}>
          <SuggestionsContext.Provider value={value}>
            <ThemesContext.Provider value={value}>
              <ImagesContext.Provider value={value}>{children}</ImagesContext.Provider>
            </ThemesContext.Provider>
          </SuggestionsContext.Provider>
        </TemplatesContext.Provider>
      </ItemsContext.Provider>
    </CategoriesContext.Provider>
  </CollectionsContext.Provider>;
}
