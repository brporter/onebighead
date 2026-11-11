import type { Item, ItemProperty } from '../../utils/types';
import { UserFlag } from '../../utils/types';
import { generateUniqueId } from '../../utils/idUtils';

/** Row identity belongs to an editing session, never to the API payload. */
export interface ItemPropertyDraft extends ItemProperty { id: string }
export type ItemDraft = Omit<Item, 'properties'> & { properties: ItemPropertyDraft[] };

export function createItemProperty(property: ItemProperty = { category: '', name: '', value: '' }): ItemPropertyDraft {
  return { ...property, id: generateUniqueId('item-prop') };
}

export function createItemDraft(item: Item): ItemDraft {
  return {
    ...item,
    userFlag: item.userFlag ?? UserFlag.Have,
    properties: (item.properties ?? []).map(createItemProperty),
    images: item.images ?? [],
  };
}

export function itemFromDraft(draft: ItemDraft): Item {
  return {
    ...draft,
    name: draft.name.trim(),
    properties: draft.properties.map(({ category, name, value }) => ({ category, name, value })),
  };
}

/** Compare editable content, independent of UI identities and server metadata. */
export function sameItemDraft(left: ItemDraft, right: ItemDraft): boolean {
  const content = (draft: ItemDraft) => JSON.stringify([
    draft.name, draft.summary, draft.description, draft.categoryId, draft.userFlag,
    draft.properties.map(({ category, name, value }) => [category, name, value]),
    draft.images.map(({ url, alt }) => [url, alt]),
  ]);
  return content(left) === content(right);
}
