import type { CollectionTheme } from '../../utils/types';

interface ThemeCardProps {
  theme: CollectionTheme;
  isSelected: boolean;
  onSelect: () => void;
}

const THEME_ICONS: Record<string, string> = {
  book: '📚',
  gamepad: '🎮',
  palette: '🎨',
  music: '💿',
  coin: '🪙',
  box: '📦',
};

function ThemeCard({ theme, isSelected, onSelect }: ThemeCardProps) {
  const icon = THEME_ICONS[theme.iconName] || '📦';
  
  // Get a preview of templates
  const templatePreview = theme.templates
    .slice(0, 1)
    .map(t => t.properties.slice(0, 3).map(p => p.name).join(', '))
    .join('');

  return (
    <button
      className={`themeCard ${isSelected ? 'themeCard--selected' : ''}`}
      onClick={onSelect}
      type="button"
    >
      <span className="themeCard__icon">{icon}</span>
      <span className="themeCard__name">{theme.name}</span>
      <span className="themeCard__description">{theme.description}</span>
      {templatePreview && (
        <span className="themeCard__preview">{templatePreview}...</span>
      )}
      {isSelected && (
        <span className="themeCard__check">✓</span>
      )}
    </button>
  );
}

export default ThemeCard;
