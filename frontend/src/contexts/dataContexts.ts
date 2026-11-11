import { createContext } from 'react';
import type { imagesApi } from '../api';
import type { useCollections } from '../data/collections/useCollections';
import type { useCategories } from '../data/categories/useCategories';
import type { useItems } from '../data/items/useItems';
import type { useTemplates } from '../data/templates/useTemplates';
import type { useSuggestions } from '../data/suggestions/useSuggestions';
import type { useThemes } from '../data/themes/useThemes';

export type CollectionsData = ReturnType<typeof useCollections>;
export type CategoriesData = ReturnType<typeof useCategories>;
export type ItemsData = ReturnType<typeof useItems>;
export type TemplatesData = ReturnType<typeof useTemplates>;
export type SuggestionsData = ReturnType<typeof useSuggestions>;
export type ThemesData = ReturnType<typeof useThemes>;
export type ImagesData = { uploadImage: typeof imagesApi.upload };

export const CollectionsContext = createContext<CollectionsData | null>(null);
export const CategoriesContext = createContext<CategoriesData | null>(null);
export const ItemsContext = createContext<ItemsData | null>(null);
export const TemplatesContext = createContext<TemplatesData | null>(null);
export const SuggestionsContext = createContext<SuggestionsData | null>(null);
export const ThemesContext = createContext<ThemesData | null>(null);
export const ImagesContext = createContext<ImagesData | null>(null);
