import { useState } from 'react';
import { useTemplatesData, useCategoriesData } from '../../contexts/useData';
import type { ItemProperty, ItemTemplate } from '../../utils/types';
import { useTemplateCatalog } from '../../data/templates/useTemplateCatalog';
import { useTemplateRecommendations } from '../../data/templates/useTemplateRecommendations';
import { ContentState } from '../common/ContentState';
import { ModalDialog } from '../common/ModalDialog';
import '../../styles/components/TemplateSelector.css';

interface TemplateSelection {
  properties: ItemProperty[];
  templateKey: string | null;
}

interface TemplateSelectorProps {
  collectionId: number;
  categoryId?: number | null;
  isOpen: boolean;
  onClose: () => void;
  onSelect: (selection: TemplateSelection) => void;
}

type TemplateGroup = 'recommended' | 'collection' | 'library';

function TemplateSelector(props: TemplateSelectorProps) {
  return props.isOpen ? <TemplateSelectorDialog key={`${props.collectionId}/${props.categoryId}`} {...props} /> : null;
}

function TemplateSelectorDialog({ collectionId, categoryId = null, onClose, onSelect }: TemplateSelectorProps) {
  const templates = useTemplatesData();
  const data = useCategoriesData();
  const catalog = useTemplateCatalog(collectionId, templates);
  const recommendations = useTemplateRecommendations(categoryId, data);
  const [selectedGroup, setSelectedGroup] = useState<TemplateGroup | null>(null);
  const category = data.categories.find(value => value.categoryId === categoryId);
  const loading = catalog.loading || recommendations.loading;
  const error = catalog.error ?? recommendations.error;
  const retry = () => { catalog.retry(); recommendations.retry(); };
  const groups: { id: TemplateGroup; label: string; templates: ItemTemplate[] }[] = [];
  if (catalog.data) {
    const recommended = catalog.data.available.filter(template => recommendations.data?.includes(template.itemTemplateId));
    if (recommended.length > 0) groups.push({ id: 'recommended', label: 'Recommended', templates: recommended });
    if (catalog.data.collection.length > 0) groups.push({ id: 'collection', label: 'Collection', templates: catalog.data.collection });
    groups.push({ id: 'library', label: 'Library', templates: catalog.data.library });
  }
  const active = groups.find(group => group.id === selectedGroup) ?? groups[0];

  return <ModalDialog onClose={onClose} label="Choose a Template" className="template-selector-dialog">
    <div className="template-selector">
      <header className="template-selector__header">
        <h2 className="template-selector__title">Choose a Template</h2>
        <button type="button" className="template-selector__close" onClick={onClose} aria-label="Close">×</button>
      </header>
      <div className="template-selector__body">
        {loading ? <ContentState kind="loading" title="Loading templates..." /> :
          error ? <ContentState kind="error" title="Unable to load templates"
            action={<button type="button" onClick={retry}>Try again</button>}>{error}</ContentState> : <>
            <div className="template-selector__groups" role="group" aria-label="Template sources">
              {groups.map(group => <button key={group.id} type="button" className="template-selector__group"
                aria-pressed={active.id === group.id} onClick={() => setSelectedGroup(group.id)}>
                {group.label} ({group.templates.length})
              </button>)}
            </div>
            {active.id === 'recommended' && category && <p className="template-selector__hint">Templates recommended for "{category.name}"</p>}
            <div className="template-selector__list">
              {active.templates.length === 0 ? <ContentState kind="empty" title="No templates available in the library." /> :
                active.templates.map(template => <button key={template.itemTemplateId} type="button" className="template-selector__item" aria-label={template.name}
                  onClick={() => onSelect({ templateKey: template.templateKey,
                    properties: template.properties.map(({ category, name }) => ({ category, name, value: '' })) })}>
                  <span className="template-selector__item-header">
                    <span className="template-selector__item-name">{template.name}</span>
                    {template.isSystem && <span className="template-selector__badge">System</span>}
                  </span>
                  {template.description && <span className="template-selector__description">{template.description}</span>}
                  <span className="template-selector__properties">
                    {template.properties.slice(0, 5).map((property, index) => <span key={index} className="template-selector__property">
                      {property.category}: {property.name}
                    </span>)}
                    {template.properties.length > 5 && <span>+{template.properties.length - 5} more</span>}
                  </span>
                </button>)}
            </div>
          </>}
      </div>
      <footer className="template-selector__footer">
        <p>A template is optional. You can add properties as you go.</p>
        <button type="button" className="detail__btn detail__btn--secondary"
          onClick={() => onSelect({ properties: [], templateKey: null })}>Start from scratch</button>
      </footer>
    </div>
  </ModalDialog>;
}

export default TemplateSelector;
