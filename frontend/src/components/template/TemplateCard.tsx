import type { ItemTemplate } from '../../utils/types';
import '../../styles/components/TemplateCard.css';

interface TemplateCardProps {
  template: ItemTemplate;
  disabled: boolean;
  onEdit: (template: ItemTemplate) => void;
  onDelete: (template: ItemTemplate) => void;
}

export function TemplateCard({ template, disabled, onEdit, onDelete }: TemplateCardProps) {
  const groups = new Map<string, string[]>();
  for (const property of template.properties) {
    const names = groups.get(property.category) ?? [];
    names.push(property.name);
    groups.set(property.category, names);
  }
  return (
    <article className="template-card" aria-label={template.name}>
      <div className="template-card__header">
        <h4 className="template-card__name">{template.name}</h4>
        {template.isSystem && <span className="template-card__badge">System</span>}
      </div>
      {template.description && <p className="template-card__description">{template.description}</p>}
      <div className="template-card__stats">
        <span><strong>{template.properties.length}</strong> {template.properties.length === 1 ? 'property' : 'properties'}</span>
        <span><strong>{groups.size}</strong> {groups.size === 1 ? 'category' : 'categories'}</span>
      </div>
      {groups.size > 0 && <div className="template-card__preview">
        {[...groups].slice(0, 3).map(([category, names]) => (
          <div key={category} className="template-card__category">
            <span className="template-card__categoryName">{category}</span>
            <span className="template-card__props">{names.slice(0, 3).join(', ')}{names.length > 3 && ` +${names.length - 3} more`}</span>
          </div>
        ))}
        {groups.size > 3 && <span className="template-card__more">+{groups.size - 3} more categories</span>}
      </div>}
      <div className="template-card__actions">
        <button type="button" className="template-card__btn" disabled={disabled} onClick={() => onEdit(template)}>
          {template.isSystem ? 'Customize' : 'Edit'}
        </button>
        {!template.isSystem && <button type="button" className="template-card__btn template-card__btn--danger"
          disabled={disabled} onClick={() => onDelete(template)}>Delete</button>}
      </div>
    </article>
  );
}
