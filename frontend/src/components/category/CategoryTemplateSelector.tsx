import { useTemplatesData } from '../../contexts/useData';
import { useTemplateCatalog } from '../../data/templates/useTemplateCatalog';
import { ContentState } from '../common/ContentState';
import { TemplateChecklist } from '../template/TemplateChecklist';

interface CategoryTemplateSelectorProps {
  collectionId: number;
  selectedTemplateIds: number[];
  onChange: (templateIds: number[]) => void;
  disabled?: boolean;
}

function CategoryTemplateSelector({ collectionId, selectedTemplateIds, onChange, disabled }: CategoryTemplateSelectorProps) {
  const catalog = useTemplateCatalog(collectionId, useTemplatesData());
  if (catalog.loading) return <ContentState kind="loading" title="Loading templates..." />;
  if (catalog.error) return <ContentState kind="error" title="Unable to load templates"
    action={<button type="button" onClick={catalog.retry}>Try again</button>}>{catalog.error}</ContentState>;
  if (catalog.data!.available.length === 0) return <ContentState kind="empty" title="No templates available." />;
  return <div className="categoryTemplateSelector">
    <p className="categoryTemplateSelector__hint">Items in this category will see these templates recommended when adding new items.</p>
    <TemplateChecklist label="Recommended templates" templates={catalog.data!.available} selectedIds={selectedTemplateIds}
      onChange={onChange} disabled={disabled} />
  </div>;
}

export default CategoryTemplateSelector;
