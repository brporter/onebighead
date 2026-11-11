import { useId } from 'react';
import type { CollectionTheme } from '../../utils/types';
import '../../styles/components/ThemeCard.css';

interface ThemeCardProps {
  theme: CollectionTheme;
  isSelected: boolean;
  onSelect: () => void;
}

const THEME_ICONS = new Map([
  ['book', '📚'],
  ['gamepad', '🎮'],
  ['palette', '🎨'],
  ['music', '💿'],
  ['coin', '🪙'],
  ['box', '📦'],
]);

function ThemeCard({ theme, isSelected, onSelect }: ThemeCardProps) {
  const id = useId();
  const icon = THEME_ICONS.get(theme.iconName) ?? '📦';
  const properties = theme.templates[0]?.properties ?? [];
  const templatePreview = properties.slice(0, 3).map(property => property.name).join(', ');

  return (
    <button
      className={`themeCard ${isSelected ? 'themeCard--selected' : ''}`}
      onClick={onSelect}
      type="button"
      aria-pressed={isSelected}
      aria-labelledby={`${id}-name`}
      aria-describedby={`${id}-description`}
    >
      <span className="themeCard__icon" aria-hidden="true">{icon}</span>
      <span id={`${id}-name`} className="themeCard__name">{theme.name}</span>
      <span id={`${id}-description`} className="themeCard__description">{theme.description}</span>
      {templatePreview && (
        <span className="themeCard__preview">{templatePreview}{properties.length > 3 ? '…' : ''}</span>
      )}
      {isSelected && (
        <span className="themeCard__check" aria-hidden="true">✓</span>
      )}
    </button>
  );
}

export default ThemeCard;
