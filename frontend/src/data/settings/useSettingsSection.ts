import { useSearchParams } from 'react-router-dom';

const sections = [
  { id: 'dashboard', label: 'Dashboard', icon: '📊', adminOnly: false },
  { id: 'collections', label: 'Collections', icon: '📚', adminOnly: false },
  { id: 'templates', label: 'Item Templates', icon: '📋', adminOnly: true },
  { id: 'team', label: 'Team Members', icon: '👥', adminOnly: true },
  { id: 'export', label: 'Data Export', icon: '📦', adminOnly: true },
  { id: 'workspaces', label: 'My Workspaces', icon: '🏢', adminOnly: false },
  { id: 'support', label: 'Support', icon: '💬', adminOnly: false },
  { id: 'account', label: 'Account', icon: '👤', adminOnly: false },
] as const;

export type SettingsSection = typeof sections[number]['id'];

/** The URL is the source of truth for tabs, deep links and browser history. */
export function useSettingsSection(isAdmin: boolean) {
  const [searchParams, setSearchParams] = useSearchParams();
  const navItems = sections.filter(section => !section.adminOnly || isAdmin);
  const activeSection = navItems.find(section => section.id === searchParams.get('section'))?.id ?? 'dashboard';

  function setSection(section: SettingsSection) {
    if (section === activeSection || !navItems.some(item => item.id === section)) return;
    const next = new URLSearchParams(searchParams);
    next.set('section', section);
    setSearchParams(next);
  }

  return { activeSection, navItems, setSection };
}
