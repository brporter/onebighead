import type { CollectionTheme } from '../../utils/types';
import { ContentState } from '../common/ContentState';
import ThemeCard from './ThemeCard';

interface SetupThemePickerProps {
  themes: CollectionTheme[];
  loading: boolean;
  error: string | null;
  retry: () => void;
  selectedId: number | undefined;
  select: (id: number) => void;
}

export function SetupThemePicker({ themes, loading, error, retry, selectedId, select }: SetupThemePickerProps) {
  if (loading) return <ContentState kind="loading" title="Loading themes..." />;
  if (error) return <ContentState kind="error" title="Unable to load themes" action={<button type="button" onClick={retry}>Try again</button>}>{error}</ContentState>;
  if (!themes.length) return <ContentState kind="empty" title="No themes available" action={<button type="button" onClick={retry}>Try again</button>} />;
  return <div className="setupWizard__themeGrid" role="group" aria-label="Collection themes">{themes.map(theme => <ThemeCard key={theme.themeId} theme={theme}
    isSelected={selectedId === theme.themeId} onSelect={() => select(theme.themeId)} />)}</div>;
}
