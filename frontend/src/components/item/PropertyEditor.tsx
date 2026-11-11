import { useEffect, useId, useRef } from 'react';
import { useSuggestionsData } from '../../contexts/useData';
import { SortablePropertyList, type FieldConfig } from '../common/SortablePropertyList';
import { createItemProperty, type ItemPropertyDraft } from '../../data/items/itemDraft';
import '../../styles/components/PropertyEditor.css';

interface PropertyEditorProps {
  properties: ItemPropertyDraft[];
  onChange: (properties: ItemPropertyDraft[]) => void;
}

const CLASS_NAMES = {
  list: 'propertyEditor__list',
  categoryHeader: 'propertyEditor__categoryHeader',
  row: 'propertyEditor__row',
  rowDragging: 'propertyEditor__row--dragging',
  rowOverlay: 'propertyEditor__row--overlay',
  input: 'propertyEditor__input',
  removeButton: 'propertyEditor__remove',
};

function PropertyEditor({ properties, onChange }: PropertyEditorProps) {
  const { propertyCategorySuggestions, propertyNameSuggestions, addLocalCategorySuggestion, addLocalNameSuggestion } = useSuggestionsData();
  const id = useId();
  const root = useRef<HTMLElement>(null);
  const pendingFocus = useRef<string | null>(null);
  const fields: FieldConfig[] = [
    { field: 'category', label: 'Property category', placeholder: 'Category', className: 'propertyEditor__input--category', datalistId: `${id}-categories` },
    { field: 'name', label: 'Property name', placeholder: 'Name', className: 'propertyEditor__input--name', datalistId: `${id}-names` },
    { field: 'value', label: 'Property value', placeholder: 'Value', className: 'propertyEditor__input--value' },
  ];

  useEffect(() => {
    if (pendingFocus.current) {
      root.current!.querySelector<HTMLInputElement>(`[data-property-id="${pendingFocus.current}"][data-field="category"]`)?.focus();
      pendingFocus.current = null;
    }
  });

  function handleFieldBlur(propertyId: string, field: keyof ItemPropertyDraft) {
    const property = properties.find(row => row.id === propertyId)!;
    if (field === 'category' && property.category.trim()) addLocalCategorySuggestion(property.category);
    if (field === 'name' && property.name.trim()) addLocalNameSuggestion(property.name);
  }

  function handleAddProperty() {
    const property = createItemProperty();
    pendingFocus.current = property.id;
    onChange([...properties, property]);
  }

  return <section className="propertyEditor" ref={root} aria-labelledby={`${id}-heading`}>
    <h3 className="propertyEditor__label" id={`${id}-heading`}>Properties</h3>
    <p className="propertyEditor__hint">Add a category, name and value. Drag properties within a category to reorder them.</p>
    {properties.length === 0 ? <div className="propertyEditor__empty">
      <p>No properties yet. Add properties to describe your item.</p>
    </div> : <SortablePropertyList
      properties={properties} fields={fields} classNames={CLASS_NAMES}
      onPropertiesChange={onChange}
      onFieldChange={(propertyId, field, value) => onChange(properties.map(property => property.id === propertyId ? { ...property, [field]: value } : property))}
      onFieldBlur={handleFieldBlur}
      onRemove={propertyId => onChange(properties.filter(property => property.id !== propertyId))}
    />}
    <button type="button" className="propertyEditor__add" onClick={handleAddProperty}>+ Add Property</button>
    <datalist id={`${id}-categories`}>
      {propertyCategorySuggestions.map(category => <option key={category} value={category} />)}
    </datalist>
    <datalist id={`${id}-names`}>
      {propertyNameSuggestions.map(name => <option key={name} value={name} />)}
    </datalist>
  </section>;
}

export default PropertyEditor;
