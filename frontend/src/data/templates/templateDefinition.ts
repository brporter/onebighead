import type { CreateItemTemplateRequest, ItemTemplate } from '../../utils/types';
import type { PropertyIdentifierDto, PropertyRenameMappingDto } from '../../api/bulkUpdates';
import { generateUniqueId } from '../../utils/idUtils';
import { samePropertySchema } from '../bulkUpdates/propertySchema';

export interface TemplatePropertyDraft extends PropertyIdentifierDto { id: string }
export interface TemplateDraft {
  name: string;
  description: string;
  properties: TemplatePropertyDraft[];
}
export interface TemplatePropertyChanges {
  oldProperties: PropertyIdentifierDto[];
  newProperties: PropertyIdentifierDto[];
  renameMappings: PropertyRenameMappingDto[];
}

export function newTemplateProperty(): TemplatePropertyDraft {
  return { id: generateUniqueId('prop'), category: '', name: '' };
}

export function createTemplateDraft(template: ItemTemplate | null): TemplateDraft {
  if (template === null) return { name: '', description: '', properties: [] };
  return { name: template.name, description: template.description,
    properties: template.properties.map(property => ({ ...newTemplateProperty(), category: property.category, name: property.name })) };
}

export function sameTemplateDraft(previous: TemplateDraft, next: TemplateDraft) {
  return previous.name === next.name && previous.description === next.description &&
    samePropertySchema(previous.properties, next.properties);
}

const identify = ({ category, name }: PropertyIdentifierDto) => ({ category: category.trim(), name: name.trim() });

export function templateRequest(draft: TemplateDraft): CreateItemTemplateRequest {
  const name = draft.name.trim();
  if (!name) throw new Error('Name is required');
  const properties = draft.properties.map(identify);
  if (properties.some(property => !property.category || !property.name)) {
    throw new Error('All properties must have a category and name');
  }
  const identifiers = properties.map(property => JSON.stringify([property.category, property.name]));
  if (new Set(identifiers).size !== identifiers.length) {
    throw new Error('Each property must have a unique category and name');
  }
  return { name, description: draft.description.trim(), properties };
}

export function templatePropertyChanges(previous: TemplateDraft, next: TemplateDraft): TemplatePropertyChanges | null {
  const oldProperties = previous.properties.map(identify);
  const newProperties = next.properties.map(identify);
  if (samePropertySchema(oldProperties, newProperties)) return null;
  const renameMappings = next.properties.flatMap(property => {
    const original = previous.properties.find(candidate => candidate.id === property.id);
    if (!original) return [];
    const old = identify(original);
    const updated = identify(property);
    if (samePropertySchema([old], [updated])) return [];
    return [{ oldCategory: old.category, oldName: old.name, newCategory: updated.category, newName: updated.name }];
  });
  return { oldProperties, newProperties, renameMappings };
}
