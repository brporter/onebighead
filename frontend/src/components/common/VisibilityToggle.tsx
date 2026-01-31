import { useEffect, useState } from 'react';
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

export default function VisibilityToggle({
  visibility,
  effectiveIsPublic,
  parentIsPublic,
  onChange,
  label = 'Visibility',
  isCollection = false,
}: VisibilityToggleProps) {
  const [localValue, setLocalValue] = useState<'inherit' | 'public' | 'private'>(
    isCollection
      ? (visibility === Visibility.Public ? 'public' : 'private')
      : (visibility === Visibility.Default ? 'inherit' : visibility === Visibility.Public ? 'public' : 'private')
  );

  useEffect(() => {
    if (isCollection) {
      setLocalValue(visibility === Visibility.Public ? 'public' : 'private');
    } else {
      setLocalValue(visibility === Visibility.Default ? 'inherit' : visibility === Visibility.Public ? 'public' : 'private');
    }
  }, [visibility, isCollection]);

  const handleChange = (newValue: 'inherit' | 'public' | 'private') => {
    setLocalValue(newValue);
    if (isCollection) {
      onChange(newValue === 'public' ? Visibility.Public : Visibility.Private);
    } else {
      if (newValue === 'inherit') {
        onChange(Visibility.Default);
      } else {
        onChange(newValue === 'public' ? Visibility.Public : Visibility.Private);
      }
    }
  };

  const canOverride = parentIsPublic || isCollection;
  const inheritedText = parentIsPublic ? 'Public' : 'Private';

  return (
    <div className="visibility-toggle">
      <label className="visibility-label">{label}</label>
      <div className="visibility-options">
        {!isCollection && (
          <button
            type="button"
            className={`visibility-option ${localValue === 'inherit' ? 'selected' : ''}`}
            onClick={() => canOverride && handleChange('inherit')}
            disabled={!canOverride && localValue !== 'inherit'}
            title={`Inherit from parent (${inheritedText})`}
          >
            Inherit ({inheritedText})
          </button>
        )}
        <button
          type="button"
          className={`visibility-option ${localValue === 'public' ? 'selected' : ''}`}
          onClick={() => canOverride && handleChange('public')}
          disabled={!canOverride}
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
      {!canOverride && !isCollection && (
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
