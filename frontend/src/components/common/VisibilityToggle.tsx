import { Visibility } from '../../utils/types';

export interface VisibilityToggleProps {
  /** Current visibility setting */
  visibility: Visibility;
  /** Computed effective visibility */
  effectiveIsPublic: boolean;
  /** Whether the parent is public (allows override) */
  parentIsPublic: boolean;
  /** Callback when visibility changes */
  onChange: (value: Visibility) => void;
  /** Label for the toggle */
  label?: string;
  /** True if this is a collection (no inherit option) */
  isCollection?: boolean;
}

function visibilityToLocal(visibility: Visibility): 'public' | 'private' {
  return visibility === Visibility.Public ? 'public' : 'private';
}

export default function VisibilityToggle({
  visibility,
  effectiveIsPublic,
  parentIsPublic,
  onChange,
  label = 'Visibility',
  isCollection = false,
}: VisibilityToggleProps) {
  // Derive local value directly from visibility prop - no local state needed
  const localValue = visibilityToLocal(visibility);

  const handleChange = (newValue: 'public' | 'private') => {
    onChange(newValue === 'public' ? Visibility.Public : Visibility.Private);
  };

  const canSetPublic = parentIsPublic || isCollection;

  return (
    <div className="visibility-toggle">
      <label className="visibility-label">{label}</label>
      <div className="visibility-options">
        <button
          type="button"
          className={`visibility-option ${localValue === 'public' ? 'selected' : ''}`}
          onClick={() => canSetPublic && handleChange('public')}
          disabled={!canSetPublic}
          title="Mark as public"
        >
          Public
        </button>
        <button
          type="button"
          className={`visibility-option ${localValue === 'private' ? 'selected' : ''}`}
          onClick={() => handleChange('private')}
          title="Mark as private"
        >
          Private
        </button>
      </div>
      {!canSetPublic && !isCollection && (
        <div className="visibility-note">
          Parent is private; cannot override to public
        </div>
      )}
      <div className="visibility-effective">
        Effective: <span className={effectiveIsPublic ? 'public' : 'private'}>
          {effectiveIsPublic ? 'Public' : 'Private'}
        </span>
      </div>
    </div>
  );
}
