import type { ItemProperty } from './types';

interface PropertyEditorProps {
  properties: ItemProperty[];
  onChange: (properties: ItemProperty[]) => void;
}

function PropertyEditor({ properties, onChange }: PropertyEditorProps) {
  function handlePropertyChange(index: number, field: keyof ItemProperty, value: string) {
    const updated = properties.map((prop, i) =>
      i === index ? { ...prop, [field]: value } : prop
    );
    onChange(updated);
  }

  function handleAddProperty() {
    onChange([...properties, { category: '', name: '', value: '' }]);
  }

  function handleRemoveProperty(index: number) {
    onChange(properties.filter((_, i) => i !== index));
  }

  return (
    <div className="propertyEditor">
      <label className="propertyEditor__label">Properties</label>
      {properties.map((prop, index) => (
        <div key={index} className="propertyEditor__row">
          <input
            type="text"
            className="propertyEditor__input propertyEditor__input--category"
            placeholder="Category"
            value={prop.category}
            onChange={(e) => handlePropertyChange(index, 'category', e.target.value)}
          />
          <input
            type="text"
            className="propertyEditor__input propertyEditor__input--name"
            placeholder="Name"
            value={prop.name}
            onChange={(e) => handlePropertyChange(index, 'name', e.target.value)}
          />
          <input
            type="text"
            className="propertyEditor__input propertyEditor__input--value"
            placeholder="Value"
            value={prop.value}
            onChange={(e) => handlePropertyChange(index, 'value', e.target.value)}
          />
          <button
            type="button"
            className="propertyEditor__remove"
            onClick={() => handleRemoveProperty(index)}
            aria-label="Remove property"
          >
            ×
          </button>
        </div>
      ))}
      <button
        type="button"
        className="propertyEditor__add"
        onClick={handleAddProperty}
      >
        + Add Property
      </button>
    </div>
  );
}

export default PropertyEditor;

