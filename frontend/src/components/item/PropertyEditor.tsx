import { useState, useMemo } from 'react';
import type { ItemProperty } from '../../utils/types';
import { useData } from '../../contexts/DataContext';
import { SortablePropertyList, type PropertyWithValue, type FieldConfig } from '../common';
import { generateUniqueId } from '../../utils/idUtils';

interface PropertyEditorProps {
  properties: ItemProperty[];
  onChange: (properties: ItemProperty[]) => void;
}

const FIELD_CONFIG: FieldConfig[] = [
  { field: 'category', placeholder: 'Category', className: 'propertyEditor__input--category', datalistId: 'property-category-suggestions' },
  { field: 'name', placeholder: 'Name', className: 'propertyEditor__input--name', datalistId: 'property-name-suggestions' },
  { field: 'value', placeholder: 'Value', className: 'propertyEditor__input--value' },
];

const CLASS_NAMES = {
  list: 'propertyEditor__list',
  categoryGroup: 'propertyEditor__categoryGroup',
  categoryHeader: 'propertyEditor__categoryHeader',
  row: 'propertyEditor__row',
  rowDragging: 'propertyEditor__row--dragging',
  rowOverlay: 'propertyEditor__row--overlay',
  input: 'propertyEditor__input',
  removeButton: 'propertyEditor__remove',
};

function PropertyEditor({ properties, onChange }: PropertyEditorProps) {
  const {
    propertyCategorySuggestions,
    propertyNameSuggestions,
    addLocalCategorySuggestion,
    addLocalNameSuggestion,
  } = useData();

  // Add stable IDs to properties for drag-and-drop
  const [propertyIds] = useState<Map<number, string>>(() => new Map());

  const propertiesWithIds = useMemo(() => {
    // Clean up IDs for removed properties
    if (properties.length < propertyIds.size) {
      const newIds = new Map<number, string>();
      properties.forEach((_, index) => {
        if (propertyIds.has(index)) {
          newIds.set(index, propertyIds.get(index)!);
        }
      });
      propertyIds.clear();
      newIds.forEach((id, index) => propertyIds.set(index, id));
    }

    return properties.map((prop, index) => {
      if (!propertyIds.has(index)) {
        propertyIds.set(index, generateUniqueId('item-prop'));
      }
      return {
        ...prop,
        id: propertyIds.get(index)!,
      };
    });
  }, [properties, propertyIds]);

  // Reset ID map when properties are cleared
  useMemo(() => {
    if (properties.length === 0) {
      propertyIds.clear();
    }
  }, [properties.length, propertyIds]);

  function handleFieldChange(id: string, field: keyof PropertyWithValue, value: string) {
    const index = propertiesWithIds.findIndex((p) => p.id === id);
    if (index === -1) return;

    const updated = properties.map((prop, i) =>
      i === index ? { ...prop, [field]: value } : prop
    );
    onChange(updated);
  }

  function handleFieldBlur(id: string, field: keyof PropertyWithValue) {
    const prop = propertiesWithIds.find((p) => p.id === id);
    if (field === 'category' && prop?.category?.trim()) {
      addLocalCategorySuggestion(prop.category);
    }
    if (field === 'name' && prop?.name?.trim()) {
      addLocalNameSuggestion(prop.name);
    }
  }

  function handleAddProperty() {
    onChange([...properties, { category: '', name: '', value: '' }]);
  }

  function handleRemoveProperty(id: string) {
    const index = propertiesWithIds.findIndex((p) => p.id === id);
    if (index === -1) return;

    // Update ID map - shift IDs after removed index
    const newIds = new Map<number, string>();
    propertyIds.forEach((idVal, idx) => {
      if (idx < index) {
        newIds.set(idx, idVal);
      } else if (idx > index) {
        newIds.set(idx - 1, idVal);
      }
    });
    propertyIds.clear();
    newIds.forEach((idVal, idx) => propertyIds.set(idx, idVal));

    onChange(properties.filter((_, i) => i !== index));
  }

  function handlePropertiesReorder(newPropertiesWithIds: PropertyWithValue[]) {
    // Update the ID map to match new order
    propertyIds.clear();
    newPropertiesWithIds.forEach((prop, index) => {
      propertyIds.set(index, prop.id);
    });

    // Extract just the property data (without ids)
    const newProperties = newPropertiesWithIds.map(({ category, name, value }) => ({
      category,
      name,
      value,
    }));
    onChange(newProperties);
  }

  return (
    <div className="propertyEditor">
      <label className="propertyEditor__label">Properties</label>

      {properties.length === 0 ? (
        <div className="propertyEditor__empty">
          <p>No properties yet. Add properties to describe your item.</p>
        </div>
      ) : (
        <SortablePropertyList
          properties={propertiesWithIds}
          fields={FIELD_CONFIG}
          classNames={CLASS_NAMES}
          onPropertiesChange={handlePropertiesReorder}
          onFieldChange={handleFieldChange}
          onFieldBlur={handleFieldBlur}
          onRemove={handleRemoveProperty}
        />
      )}

      <button
        type="button"
        className="propertyEditor__add"
        onClick={handleAddProperty}
      >
        + Add Property
      </button>

      {/* HTML5 datalist for property category suggestions */}
      <datalist id="property-category-suggestions">
        {propertyCategorySuggestions.map((category) => (
          <option key={category} value={category} />
        ))}
      </datalist>

      {/* HTML5 datalist for property name suggestions */}
      <datalist id="property-name-suggestions">
        {propertyNameSuggestions.map((name) => (
          <option key={name} value={name} />
        ))}
      </datalist>
    </div>
  );
}

export default PropertyEditor;
