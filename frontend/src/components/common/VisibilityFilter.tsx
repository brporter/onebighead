import '../../styles/components/visibility-filter.css';

export type VisibilityFilterValue = 'all' | 'public' | 'private';

interface VisibilityFilterProps {
  value: VisibilityFilterValue;
  onChange: (filter: VisibilityFilterValue) => void;
  totalCount: number;
  filteredCount: number;
}

export function VisibilityFilter({ value, onChange, filteredCount }: VisibilityFilterProps) {
  return (
    <div className="filter-bar" role="group" aria-label="Visibility filter">
      <button
        type="button"
        className={`filter-btn${value === 'all' ? ' active' : ''}`}
        onClick={() => onChange('all')}
        aria-pressed={value === 'all'}
      >
        All
      </button>
      <button
        type="button"
        className={`filter-btn${value === 'public' ? ' active' : ''}`}
        onClick={() => onChange('public')}
        aria-pressed={value === 'public'}
      >
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z" />
        </svg>
        Public
      </button>
      <button
        type="button"
        className={`filter-btn${value === 'private' ? ' active' : ''}`}
        onClick={() => onChange('private')}
        aria-pressed={value === 'private'}
      >
        Private
      </button>
      <span className="filter-count">Showing {filteredCount} items</span>
    </div>
  );
}
