import { useId, useMemo } from 'react';
import type { Category } from '../../utils/types';
import { CategoryHierarchy } from '../../data/categories/CategoryHierarchy';

interface CategorySelectorProps {
  categories: Category[];
  selectedCategoryId: number | null;
  onChange: (categoryId: number | null) => void;
  label?: string;
  allowNull?: boolean;
  nullLabel?: string;
  variant?: 'detail' | 'modal';
}

function CategorySelector({ categories, selectedCategoryId, onChange, label = 'Category',
  allowNull = true, nullLabel = 'No category', variant = 'detail' }: CategorySelectorProps) {
  const id = useId();
  const hierarchy = useMemo(() => new CategoryHierarchy(categories), [categories]);
  const missing = selectedCategoryId !== null && !hierarchy.byId.has(selectedCategoryId);
  return <div className={`${variant}__field`}>
    <label htmlFor={id} className={`${variant}__label`}>{label}</label>
    <select id={id} className={variant === 'modal' ? 'modal__select' : 'detail__input'} value={selectedCategoryId ?? ''} aria-invalid={missing || undefined}
      onChange={event => onChange(event.target.value ? Number(event.target.value) : null)}>
      <option value="" disabled={!allowNull}>{allowNull ? nullLabel : 'Select a category'}</option>
      {missing && <option value={selectedCategoryId!} disabled>Unavailable category ({selectedCategoryId})</option>}
      {hierarchy.rows.map(({ category, depth }) => <option key={category.categoryId} value={category.categoryId}>
        {'  '.repeat(Math.min(depth, 5))}{depth > 0 ? '└ ' : ''}{category.name}
      </option>)}
    </select>
  </div>;
}

export default CategorySelector;
