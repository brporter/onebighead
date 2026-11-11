import type { Category, Item, ItemProperty } from '../../utils/types';
import type { bulkUpdatesApi } from '../../api/bulkUpdates';
import type { ItemPropertyChangeOffer, ScopeOption } from '../bulkUpdates/types';
import { samePropertySchema } from '../bulkUpdates/propertySchema';

/** Property order belongs to the schema; values belong only to the edited item. */
export async function previewPropertyChanges(
  previous: ItemProperty[], item: Item, categories: Category[],
  gateway: Pick<typeof bulkUpdatesApi, 'preview'>, signal: AbortSignal,
): Promise<ItemPropertyChangeOffer | null> {
  if (samePropertySchema(previous, item.properties)) return null;

  const scopes: Omit<ScopeOption, 'count'>[] = [];
  if (item.categoryId !== null) scopes.push({
    scope: 'category', categoryId: item.categoryId,
    label: `in "${categories.find(category => category.categoryId === item.categoryId)?.name ?? 'this category'}"`,
  });
  scopes.push({ scope: 'collection', collectionId: item.collectionId, label: 'in this collection' });
  const scopeOptions = await Promise.all(scopes.map(async option => {
    const result = await gateway.preview({ scope: option.scope, categoryId: option.categoryId,
      collectionId: option.collectionId, excludeItemId: item.id! }, { signal });
    return { ...option, count: result.affectedItemCount };
  }));
  const eligible = scopeOptions.filter(option => option.count > 0);
  if (eligible.length === 0) return null;
  const identify = ({ category, name }: ItemProperty) => ({ category, name });
  return { scopeOptions: eligible, oldProperties: previous.map(identify),
    newProperties: item.properties.map(identify), excludeItemId: item.id! };
}
