import { useId, type Dispatch, type SetStateAction } from 'react';
import { SortablePropertyList, type FieldConfig } from '../common/SortablePropertyList';
import { newTemplateProperty, type TemplateDraft, type TemplatePropertyDraft } from '../../data/templates/templateDefinition';
import '../../styles/components/TemplateDefinitionForm.css';

const FIELDS: FieldConfig[] = [
  { field: 'category', label: 'Property category', placeholder: 'e.g., Specs, Details' },
  { field: 'name', label: 'Property name', placeholder: 'e.g., CPU, Author' },
];
const CLASSES = {
  list: 'template-form__propertyList',
  categoryHeader: 'template-form__categoryHeader', row: 'template-form__propertyRow',
  rowDragging: 'template-form__propertyRow--dragging', rowOverlay: 'template-form__propertyRow--overlay',
  input: 'template-form__input', removeButton: 'template-form__removeBtn',
};
interface TemplateDraftFormProps {
  title: string;
  notice?: string;
  draft: TemplateDraft;
  setDraft: Dispatch<SetStateAction<TemplateDraft>>;
  saving: boolean;
  error: string | null;
  saveLabel: string;
  onSave: () => void | Promise<void>;
  onCancel: () => void;
}

export function TemplateDraftForm({ title, notice, draft, setDraft, saving, error, saveLabel, onSave, onCancel }: TemplateDraftFormProps) {
  const id = useId();
  const changeProperty = (propertyId: string, field: keyof TemplatePropertyDraft, value: string) =>
    setDraft(previous => ({ ...previous, properties: previous.properties.map(property =>
      property.id === propertyId ? { ...property, [field]: value } : property) }));

  return <form className="template-form" aria-label="Template definition" aria-busy={saving} onSubmit={event => { event.preventDefault(); void onSave(); }}>
    <div className="template-form__header"><h3 className="template-form__title">
      {title}
    </h3></div>
    <fieldset className="template-form__fieldset" disabled={saving} inert={saving}>
      <legend className="template-form__legend">Template details</legend>
      <section className="template-form__section">
        <h4 className="template-form__sectionTitle">Basic Information</h4>
        {notice && <p className="template-form__sectionHint">{notice}</p>}
        <div className="template-form__fields">
          <div className="template-form__field">
            <label className="template-form__label" htmlFor={`${id}-name`}>Template Name <span aria-hidden="true">*</span></label>
            <input id={`${id}-name`} className="template-form__input" aria-required="true" autoFocus value={draft.name}
              onChange={event => setDraft(previous => ({ ...previous, name: event.target.value }))} placeholder="e.g., Laptop, Book, Vinyl Record" />
          </div>
          <div className="template-form__field">
            <label className="template-form__label" htmlFor={`${id}-description`}>Description</label>
            <textarea id={`${id}-description`} className="template-form__textarea" rows={2} value={draft.description}
              onChange={event => setDraft(previous => ({ ...previous, description: event.target.value }))} />
          </div>
        </div>
      </section>
      <section className="template-form__section">
        <h4 className="template-form__sectionTitle">Properties</h4>
        <p className="template-form__sectionHint">Define the fields for your items. Group related properties under the same category.</p>
        <div className="template-form__properties">
          {draft.properties.length === 0 ? <p className="template-form__emptyProperties">No properties defined yet. Add a property to get started.</p> : <>
            <div className="template-form__propertyHeader" aria-hidden="true"><span /><span>Category</span><span>Property Name</span><span /></div>
            <SortablePropertyList properties={draft.properties} fields={FIELDS} classNames={CLASSES}
              onPropertiesChange={properties => setDraft(previous => ({ ...previous, properties }))}
              onFieldChange={changeProperty}
              onRemove={propertyId => setDraft(previous => ({ ...previous, properties: previous.properties.filter(property => property.id !== propertyId) }))} />
          </>}
          <button type="button" className="template-form__addProperty" onClick={() => setDraft(previous => ({ ...previous, properties: [...previous.properties, newTemplateProperty()] }))}>+ Add Property</button>
        </div>
      </section>
      {error && <p className="template-form__error" role="alert">{error}</p>}
      <div className="template-form__actions">
        <button type="button" className="template-form__btn template-form__btn--secondary" onClick={onCancel}>Cancel</button>
        <button type="submit" className="template-form__btn template-form__btn--primary">
          {saving ? 'Saving…' : saveLabel}
        </button>
      </div>
    </fieldset>
  </form>;
}
