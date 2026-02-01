import { TenantSwitcher } from './TenantSwitcher';

interface SiteHeaderProps {
  title?: string;
  subtitle?: string;
  children?: React.ReactNode;
  showTenantSwitcher?: boolean;
}

export function SiteHeader({
  title,
  subtitle,
  children,
  showTenantSwitcher = true
}: SiteHeaderProps) {
  return (
    <header className="site-header">
      <div className="site-header__content">
        <div className="site-header__brand">
          <a href="/" className="site-header__logo">OneBigHead</a>
          {showTenantSwitcher && <TenantSwitcher />}
        </div>
        {title && (
          <div className="site-header__title-area">
            <h1 className="site-header__title">{title}</h1>
            {subtitle && <p className="site-header__subtitle">{subtitle}</p>}
          </div>
        )}
        {!title && <div className="site-header__spacer" />}
        <div className="site-header__actions">
          {children}
        </div>
      </div>
    </header>
  );
}

export default SiteHeader;
