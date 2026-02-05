import { WorkspaceSwitcher } from './WorkspaceSwitcher';

interface SiteHeaderProps {
  title?: string;
  subtitle?: string;
  children?: React.ReactNode;
  showWorkspaceSwitcher?: boolean;
  backLink?: {
    label: string;
    onClick: () => void;
  };
}

export function SiteHeader({
  title,
  subtitle,
  children,
  showWorkspaceSwitcher = true,
  backLink
}: SiteHeaderProps) {
  return (
    <header className="site-header">
      <div className="site-header__content">
        <div className="site-header__brand">
          <a href="/" className="site-header__logo">OneBigHead</a>
          {showWorkspaceSwitcher && <WorkspaceSwitcher />}
        </div>
        {(title || backLink) && (
          <div className="site-header__title-area">
            {backLink && (
              <button className="site-header__back" onClick={backLink.onClick}>
                ← {backLink.label}
              </button>
            )}
            {title && <h1 className="site-header__title">{title}</h1>}
            {subtitle && <p className="site-header__subtitle">{subtitle}</p>}
          </div>
        )}
        {!title && !backLink && <div className="site-header__spacer" />}
        <div className="site-header__actions">
          {children}
        </div>
      </div>
    </header>
  );
}

export default SiteHeader;
