import { useId, useState, type ReactNode } from 'react';
import '../../styles/components/CollectionLayout.css';

interface CollectionLayoutProps {
  sidebar: ReactNode;
  header: ReactNode;
  children: ReactNode;
}

/** Keeps navigation reachable at every viewport, independently of route content. */
export function CollectionLayout({ sidebar, header, children }: CollectionLayoutProps) {
  const [collapsed, setCollapsed] = useState(() => window.matchMedia('(max-width: 1024px)').matches);
  const navigationId = useId();
  return <div className={`collection-layout${collapsed ? ' collection-layout--collapsed' : ''}`}>
    <nav className="collection-layout__sidebar" aria-label="Category navigation">
      <button type="button" className="collection-layout__toggle"
        aria-label={collapsed ? 'Expand sidebar' : 'Collapse categories'}
        aria-expanded={!collapsed} aria-controls={navigationId}
        onClick={() => setCollapsed(value => !value)}>
        <span aria-hidden="true">{collapsed ? '+' : '−'}</span>
        <span className="collection-layout__toggle-label">{collapsed ? 'Categories' : 'Hide categories'}</span>
      </button>
      <div id={navigationId}>{!collapsed && sidebar}</div>
    </nav>
    <main className="collection-layout__content">
      {header}
      {children}
    </main>
  </div>;
}
