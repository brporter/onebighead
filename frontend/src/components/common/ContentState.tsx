import type { ReactNode } from 'react';
import '../../styles/components/ContentState.css';

interface ContentStateProps {
  kind: 'loading' | 'error' | 'empty';
  title: string;
  children?: ReactNode;
  action?: ReactNode;
}

/** Consistent, accessible feedback for page and panel content. */
export function ContentState({ kind, title, children, action }: ContentStateProps) {
  return (
    <div className={`content-state content-state--${kind}`} role={kind === 'error' ? 'alert' : 'status'}>
      <span className="content-state__symbol" aria-hidden="true">{kind === 'loading' ? '…' : kind === 'error' ? '!' : '◇'}</span>
      <p className="content-state__title">{title}</p>
      {children && <div className="content-state__description">{children}</div>}
      {action && <div className="content-state__action">{action}</div>}
    </div>
  );
}
