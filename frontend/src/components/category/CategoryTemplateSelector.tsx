import { useState, useEffect } from 'react';
import { useData } from '../../contexts/DataContext';
import type { ItemTemplate } from '../../utils/types';

interface CategoryTemplateSelectorProps {
  collectionId: number;
  selectedTemplateIds: number[];
  onChange: (templateIds: number[]) => void;
  disabled?: boolean;
}

function CategoryTemplateSelector({ collectionId, selectedTemplateIds, onChange, disabled }: CategoryTemplateSelectorProps) {
  const { loadCollectionTemplates, loadItemTemplates, itemTemplates } = useData();
  const [collectionTemplates, setCollectionTemplates] = useState<ItemTemplate[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    Promise.all([
      loadCollectionTemplates(collectionId),
      loadItemTemplates(),
    ]).then(([colTemplates]) => {
      setCollectionTemplates(colTemplates);
      setLoading(false);
    });
  }, [collectionId, loadCollectionTemplates, loadItemTemplates]);

  // Combine collection templates and library templates, deduplicating
  const availableTemplates = [...collectionTemplates];
  itemTemplates.forEach(t => {
    if (!availableTemplates.some(ct => ct.itemTemplateId === t.itemTemplateId)) {
      availableTemplates.push(t);
    }
  });
  availableTemplates.sort((a, b) => a.name.localeCompare(b.name));

  const handleToggleTemplate = (templateId: number) => {
    if (disabled) return;
    
    if (selectedTemplateIds.includes(templateId)) {
      onChange(selectedTemplateIds.filter(id => id !== templateId));
    } else {
      onChange([...selectedTemplateIds, templateId]);
    }
  };

  if (loading) {
    return <p className="categoryTemplateSelector__loading">Loading templates...</p>;
  }

  if (availableTemplates.length === 0) {
    return <p className="categoryTemplateSelector__empty">No templates available.</p>;
  }

  return (
    <div className="categoryTemplateSelector">
      <p className="categoryTemplateSelector__hint">
        Items in this category will see these templates recommended when adding new items.
      </p>
      <div className="categoryTemplateSelector__list">
        {availableTemplates.map((template) => (
          <label
            key={template.itemTemplateId}
            className={`categoryTemplateSelector__item ${disabled ? 'categoryTemplateSelector__item--disabled' : ''}`}
          >
            <input
              type="checkbox"
              className="categoryTemplateSelector__checkbox"
              checked={selectedTemplateIds.includes(template.itemTemplateId)}
              onChange={() => handleToggleTemplate(template.itemTemplateId)}
              disabled={disabled}
            />
            <div className="categoryTemplateSelector__itemContent">
              <span className="categoryTemplateSelector__itemName">{template.name}</span>
              {template.isSystem && (
                <span className="categoryTemplateSelector__systemBadge">System</span>
              )}
              {template.description && (
                <span className="categoryTemplateSelector__itemDescription">{template.description}</span>
              )}
            </div>
          </label>
        ))}
      </div>
    </div>
  );
}

export default CategoryTemplateSelector;
