import type { Category } from './types';

interface SubcategoryDropdownProps {
  subcategories?: Category[];
  selectedId: number | null;
  onChange: (id: number | null) => void;
}

function SubcategoryDropdown({ subcategories, selectedId, onChange }: SubcategoryDropdownProps) {
  if (!subcategories?.length) return null;

  return (
    <div className="subcategoryDropdown">
      <label htmlFor="subcategory-filter" className="subcategoryDropdown__label">
        Filter by subcategory:
      </label>
      <select
        id="subcategory-filter"
        className="subcategoryDropdown__select"
        value={selectedId ?? ''}
        onChange={(e) => onChange(e.target.value ? Number(e.target.value) : null)}
      >
        <option value="">All items</option>
        {subcategories.map((cat) => (
          <option key={cat.categoryId} value={cat.categoryId}>
            {cat.name}
          </option>
        ))}
      </select>
    </div>
  );
}

export default SubcategoryDropdown;

