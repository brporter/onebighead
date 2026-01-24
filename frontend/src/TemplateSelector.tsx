import { useState, useEffect } from 'react';
import { useData } from './DataContext';
import type { ItemTemplate, ItemProperty } from './types';

interface TemplateSelectorProps {
  collectionId: number;
  isOpen: boolean;
  onClose: () => void;
  onSelect: (properties: ItemProperty[]) => void;
}

function TemplateSelector({ collectionId, isOpen, onClose, onSelect }: TemplateSelectorProps) {
  const { loadCollectionTemplates, loadItemTemplates, itemTemplates } = useData();
  const [collectionTemplates, setCollectionTemplates] = useState<ItemTemplate[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'collection' | 'library'>('collection');

  useEffect(() => {
    if (isOpen) {
      setLoading(true);
      Promise.all([
        loadCollectionTemplates(collectionId),
        loadItemTemplates(),
      ]).then(([colTemplates]) => {
        setCollectionTemplates(colTemplates);
        // Default to library tab if no collection templates
        if (colTemplates.length === 0) {
          setActiveTab('library');
        } else {
          setActiveTab('collection');
        }
        setLoading(false);
      });
    }
  }, [isOpen, collectionId, loadCollectionTemplates, loadItemTemplates]);

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

  const displayTemplates = activeTab === 'collection' ? collectionTemplates : itemTemplates;

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
                {collectionTemplates.length > 0 && (
                  <button
                    className={`templateSelector__tab ${activeTab === 'collection' ? 'templateSelector__tab--active' : ''}`}
                    onClick={() => setActiveTab('collection')}
                  >
                    Collection Templates ({collectionTemplates.length})
                  </button>
                )}
                <button
                  className={`templateSelector__tab ${activeTab === 'library' ? 'templateSelector__tab--active' : ''}`}
                  onClick={() => setActiveTab('library')}
                >
                  Template Library ({itemTemplates.length})
                </button>
              </div>

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
                        {template.isShared && (
                          <span className="templateSelector__sharedBadge">Shared</span>
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
                    {activeTab === 'collection'
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
