import type { ItemTemplate } from '../../utils/types';
import '../../styles/components/TemplateChecklist.css';

interface TemplateChecklistProps {
  label: string;
  templates: ItemTemplate[];
  selectedIds: number[];
  onChange: (ids: number[]) => void;
  disabled?: boolean;
}

export function TemplateChecklist({ label, templates, selectedIds, onChange, disabled }: TemplateChecklistProps) {
  return <fieldset className="template-checklist" aria-label={label} disabled={disabled}>
    {templates.map(template => <label key={template.itemTemplateId} className="template-checklist__option">
      <input type="checkbox" aria-label={template.name} checked={selectedIds.includes(template.itemTemplateId)}
        onChange={() => onChange(selectedIds.includes(template.itemTemplateId)
          ? selectedIds.filter(id => id !== template.itemTemplateId) : [...selectedIds, template.itemTemplateId])} />
      <span className="template-checklist__content">
        <span className="template-checklist__name">{template.name}</span>
        {template.isSystem && <span className="template-checklist__badge">System</span>}
        {template.description && <span className="template-checklist__description">{template.description}</span>}
        <span className="template-checklist__count">{`${template.properties.length} ${template.properties.length === 1 ? 'property' : 'properties'}`}</span>
      </span>
    </label>)}
  </fieldset>;
}
