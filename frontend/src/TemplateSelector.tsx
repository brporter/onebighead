import { useState, useEffect } from 'react';
import { useData } from './DataContext';
import type { ItemTemplate, ItemProperty } from './types';

interface TemplateSelectorProps {
  collectionId: number;
  categoryId?: number | null;
  isOpen: boolean;
  onClose: () => void;
  onSelect: (properties: ItemProperty[]) => void;
}

function TemplateSelector({ collectionId, categoryId, isOpen, onClose, onSelect }: TemplateSelectorProps) {
  const { loadCollectionTemplates, loadItemTemplates, itemTemplates, getCategoryTemplates, categories } = useData();
  const [collectionTemplates, setCollectionTemplates] = useState<ItemTemplate[]>([]);
  const [recommendedTemplateIds, setRecommendedTemplateIds] = useState<number[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'recommended' | 'collection' | 'library'>('collection');

  const category = categoryId ? categories.find(c => c.categoryId === categoryId) : null;

  useEffect(() => {
    if (isOpen) {
      setLoading(true);
      const promises: Promise<unknown>[] = [
        loadCollectionTemplates(collectionId),
        loadItemTemplates(),
      ];
      
      // Load category templates if a category is selected
      if (categoryId) {
        promises.push(getCategoryTemplates(categoryId));
      }
      
      Promise.all(promises).then(([colTemplates, , categoryTemplateIds]) => {
        setCollectionTemplates(colTemplates as ItemTemplate[]);
        const catTemplates = (categoryTemplateIds as number[] | undefined) ?? [];
        setRecommendedTemplateIds(catTemplates);
        
        // Set default tab based on available templates
        if (catTemplates.length > 0) {
          setActiveTab('recommended');
        } else if ((colTemplates as ItemTemplate[]).length > 0) {
          setActiveTab('collection');
        } else {
          setActiveTab('library');
        }
        setLoading(false);
      });
    }
  }, [isOpen, collectionId, categoryId, loadCollectionTemplates, loadItemTemplates, getCategoryTemplates]);

  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }
    return () => {
      document.body.style.overflow = '';
    };
  }, [isOpen]);

  if (!isOpen) return null;

  const handleSelectTemplate = (template: ItemTemplate) => {
    const properties: ItemProperty[] = template.properties.map((p) => ({
      category: p.category,
      name: p.name,
      value: '',
    }));
    onSelect(properties);
  };

  const handleStartFromScratch = () => {
    onSelect([]);
  };

  const handleBackdropClick = (e: React.MouseEvent) => {
    if (e.target === e.currentTarget) {
      onClose();
    }
  };

  // Get recommended templates from both collection and library templates
  const allTemplates = [...collectionTemplates];
  itemTemplates.forEach(t => {
    if (!allTemplates.some(ct => ct.itemTemplateId === t.itemTemplateId)) {
      allTemplates.push(t);
    }
  });
  const recommendedTemplates = recommendedTemplateIds
    .map(id => allTemplates.find(t => t.itemTemplateId === id))
    .filter((t): t is ItemTemplate => t !== undefined);

  const displayTemplates = activeTab === 'recommended' 
    ? recommendedTemplates 
    : activeTab === 'collection' 
      ? collectionTemplates 
      : itemTemplates;

  const hasRecommended = recommendedTemplateIds.length > 0;

  return (
    <div className="templateSelector" onClick={handleBackdropClick}>
      <div className="templateSelector__container">
        <div className="templateSelector__header">
          <h2 className="templateSelector__title">Choose a Template</h2>
          <button className="templateSelector__close" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>

        <div className="templateSelector__body">
          {loading ? (
            <p className="templateSelector__loading">Loading templates...</p>
          ) : (
            <>
              <div className="templateSelector__tabs">
                {hasRecommended && (
                  <button
                    className={`templateSelector__tab templateSelector__tab--recommended ${activeTab === 'recommended' ? 'templateSelector__tab--active' : ''}`}
                    onClick={() => setActiveTab('recommended')}
                  >
                    ★ Recommended ({recommendedTemplates.length})
                  </button>
                )}
                {collectionTemplates.length > 0 && (
                  <button
                    className={`templateSelector__tab ${activeTab === 'collection' ? 'templateSelector__tab--active' : ''}`}
                    onClick={() => setActiveTab('collection')}
                  >
                    Collection ({collectionTemplates.length})
                  </button>
                )}
                <button
                  className={`templateSelector__tab ${activeTab === 'library' ? 'templateSelector__tab--active' : ''}`}
                  onClick={() => setActiveTab('library')}
                >
                  Library ({itemTemplates.length})
                </button>
              </div>

              {activeTab === 'recommended' && category && (
                <p className="templateSelector__hint">
                  Templates recommended for "{category.name}"
                </p>
              )}

              <div className="templateSelector__list">
                {displayTemplates.length > 0 ? (
                  displayTemplates.map((template) => (
                    <button
                      key={template.itemTemplateId}
                      className="templateSelector__item"
                      onClick={() => handleSelectTemplate(template)}
                    >
                      <div className="templateSelector__itemHeader">
                        <span className="templateSelector__itemName">{template.name}</span>
                        {template.isSystem && (
                          <span className="templateSelector__sharedBadge">System</span>
                        )}
                      </div>
                      {template.description && (
                        <p className="templateSelector__itemDescription">{template.description}</p>
                      )}
                      <div className="templateSelector__itemProperties">
                        {template.properties.slice(0, 5).map((p, i) => (
                          <span key={i} className="templateSelector__propertyTag">
                            {p.category}: {p.name}
                          </span>
                        ))}
                        {template.properties.length > 5 && (
                          <span className="templateSelector__propertyMore">
                            +{template.properties.length - 5} more
                          </span>
                        )}
                      </div>
                    </button>
                  ))
                ) : (
                  <p className="templateSelector__empty">
                    {activeTab === 'recommended'
                      ? 'No recommended templates for this category.'
                      : activeTab === 'collection'
                        ? 'No templates associated with this collection.'
                        : 'No templates available in the library.'}
                  </p>
                )}
              </div>

              <div className="templateSelector__footer">
                <button
                  className="templateSelector__scratchButton"
                  onClick={handleStartFromScratch}
                >
                  Start from scratch
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export default TemplateSelector;
