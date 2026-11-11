import type { PropertyIdentifierDto } from '../../api/bulkUpdates';

/** Values are item data; category/name order defines the shared schema. */
export function samePropertySchema(previous: PropertyIdentifierDto[], next: PropertyIdentifierDto[]) {
  return previous.length === next.length && previous.every((property, index) =>
    property.category === next[index].category && property.name === next[index].name);
}
