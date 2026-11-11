import { useState, useEffect, useId } from 'react';
import { validateCategoryName } from '../../data/categories/categoryDraft';

interface QuickCreatePopoverProps {
  isVisible: boolean;
  onSave: (name: string) => void;
  onMoreDetails: (name: string) => void;
  onCancel: () => void;
  onHasChanges?: (dirty: boolean) => void;
  disabled?: boolean;
}

export default function QuickCreatePopover(props: QuickCreatePopoverProps) {
  return props.isVisible ? <QuickCreateForm {...props} /> : null;
}

function QuickCreateForm({ onSave, onMoreDetails, onCancel, onHasChanges, disabled = false }: QuickCreatePopoverProps) {
  const [name, setName] = useState('');
  const [error, setError] = useState<string | null>(null);
  const inputId = useId();
  const dirty = name.length > 0;
  useEffect(() => { onHasChanges?.(dirty); }, [dirty, onHasChanges]);
  return <form className="quickCreatePopover" aria-label="Create category" onSubmit={event => {
    event.preventDefault();
    if (disabled) return;
    const validation = validateCategoryName(name);
    setError(validation);
    if (!validation) onSave(name.trim());
  }} onKeyDown={event => {
    if (event.key === 'Escape') { event.stopPropagation(); event.preventDefault(); if (!disabled) onCancel(); }
  }}>
    <fieldset className="category-manager-form__fields" disabled={disabled}>
      <label className="modal__label" htmlFor={inputId}>Name</label>
      <input id={inputId} autoFocus type="text" className="quickCreatePopover__input modal__input" placeholder="Category name"
        value={name} onChange={event => { setName(event.target.value); setError(null); }} />
      {error && <div className="quickCreatePopover__error modal__error" role="alert">{error}</div>}
      <div className="quickCreatePopover__actions">
        <button type="button" className="modal__button modal__button--secondary" onClick={() => onMoreDetails(name)}>More Details...</button>
        <button type="button" className="modal__button modal__button--secondary" onClick={onCancel}>Cancel</button>
        <button type="submit" className="modal__button modal__button--primary">Save</button>
      </div>
    </fieldset>
  </form>;
}
