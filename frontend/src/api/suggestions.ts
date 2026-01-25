/**
 * Property Suggestions API
 */
import { api } from './client';

export interface PropertySuggestionsResponse {
  categories: string[];
  names: string[];
}

export const suggestionsApi = {
  get(collectionId: number): Promise<PropertySuggestionsResponse> {
    return api.get<PropertySuggestionsResponse>(
      `/collections/${collectionId}/property-suggestions`
    );
  },

  sync(collectionId: number): Promise<PropertySuggestionsResponse> {
    return api.post<PropertySuggestionsResponse>(
      `/collections/${collectionId}/property-suggestions/sync`
    );
  },
};
