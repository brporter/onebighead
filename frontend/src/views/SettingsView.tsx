import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import '../styles/App.css';
import '../styles/SettingsView.css';
import { useUser } from '../contexts/useUser';
import { dashboardApi } from '../api';
import { DashboardSection } from '../components/settings/DashboardSection';
import ItemTemplateEditor from '../components/template/ItemTemplateEditor';
import { SupportSection } from '../components/support/SupportSection';
import { AccountDeletionSection, UserButton, UserManagement } from '../components/user';
import { SupportModal } from '../components/support/SupportModal';
import { WorkspaceSettings } from '../components/workspace/WorkspaceSettings';
import { DataExportSection } from '../components/workspace/DataExportSection';
import { SiteHeader, SiteFooter } from '../components/common';
import { useSettingsSection } from '../data/settings/useSettingsSection';
import { useUnsavedNavigation } from '../data/shared/useUnsavedNavigation';
import { useSectionStatus } from '../data/settings/useSectionStatus';
import { CollectionSettings } from '../components/collection/CollectionSettings';

function SettingsView() {
  const navigate = useNavigate();
  const { user } = useUser();
  const { activeSection, navItems, setSection } = useSettingsSection(user?.isWorkspaceAdmin ?? false);
  const status = useSectionStatus(activeSection);
  const completeNavigation = useUnsavedNavigation(status.dirty, status.pending);
  const [isSupportOpen, setIsSupportOpen] = useState(false);
  const [supportRefreshKey, setSupportRefreshKey] = useState(0);

  const renderTemplatesSection = () => (
    <div className="settings-section settings-section--templates">
      <ItemTemplateEditor
        onClose={() => setSection('collections')}
        onStatusChange={status.report}
        isFullPage={true}
      />
    </div>
  );

  const renderTeamSection = () => (
    <div className="settings-section">
      <div className="settings-section__header">
        <div>
          <h2 className="settings-section__title">Team Members</h2>
          <p className="settings-section__description">
            Invite team members to collaborate on your collections.
          </p>
        </div>
      </div>
      <UserManagement onStatusChange={status.report} />
    </div>
  );

  const renderSupportSection = () => (
    <div className="settings-section settings-section--support">
      <div className="settings-section__header">
        <div>
          <h2 className="settings-section__title">Support Requests</h2>
          <p className="settings-section__description">
            View and manage your support requests. Get help with any issues you encounter.
          </p>
        </div>
      </div>
      <SupportSection
        isFullPage={true}
        onNewRequest={() => setIsSupportOpen(true)}
        refreshKey={supportRefreshKey}
        onStatusChange={status.report}
      />
    </div>
  );

  const renderAccountSection = () => (
    <div className="settings-section">
      <div className="settings-section__header">
        <div>
          <h2 className="settings-section__title">Account</h2>
          <p className="settings-section__description">
            Manage your account settings and preferences.
          </p>
        </div>
      </div>

      <div className="settings-account-info">
        <div className="settings-account-info__row">
          <span className="settings-account-info__label">Email:</span>
          <span className="settings-account-info__value">{user?.email}</span>
        </div>
      </div>

      <div className="settings-section__divider" />

      <AccountDeletionSection onStatusChange={status.report} />
    </div>
  );

  const renderContent = () => {
    switch (activeSection) {
      case 'dashboard':
        return <DashboardSection gateway={dashboardApi} />;
      case 'collections':
        return <CollectionSettings isAdmin={user?.isWorkspaceAdmin ?? false} onStatusChange={status.report} />;
      case 'templates':
        return renderTemplatesSection();
      case 'team':
        return renderTeamSection();
      case 'workspaces':
        return <WorkspaceSettings memberships={user?.workspaces ?? []} activeWorkspaceId={user?.activeWorkspace?.workspaceId} onStatusChange={status.report}
          onCreated={() => completeNavigation(() => { void navigate('/settings?section=workspaces'); })} />;
      case 'export':
        return <DataExportSection />;
      case 'support':
        return renderSupportSection();
      case 'account':
        return renderAccountSection();
    }
  };

  return (
    <div className="app">
      <SiteHeader>
        <a href="/collections" className="gallery-link" onClick={(e) => { e.preventDefault(); navigate('/collections'); }}>
          Return to Collections
        </a>
        <button className="support-link support-link--icon" onClick={() => setIsSupportOpen(true)} title="Support" aria-label="Support">
          <span className="support-link__icon">?</span>
        </button>
        <UserButton />
      </SiteHeader>

      <div className="app__layout">
        <nav className="app__sidebar settings-sidebar" aria-label="Settings navigation">
          <div className="settings-nav">
            <ul className="settings-nav__list">
              {navItems.map((item) => (
                <li key={item.id}>
                  <button
                    className={`settings-nav__item ${activeSection === item.id ? 'settings-nav__item--active' : ''}`}
                    type="button"
                    aria-current={activeSection === item.id ? 'page' : undefined}
                    disabled={status.pending}
                    onClick={() => setSection(item.id)}
                  >
                    <span className="settings-nav__icon" aria-hidden="true">{item.icon}</span>
                    <span className="settings-nav__label">{item.label}</span>
                  </button>
                </li>
              ))}
            </ul>
          </div>
        </nav>

        <main className="app__content settings-content">
          <div className="settings-title-bar">
            <h1 className="settings-title-bar__title">Settings</h1>
          </div>
          <div className="settings-panel" key={activeSection}>
            {renderContent()}
          </div>
        </main>
      </div>

      <SiteFooter />

      <SupportModal
        isOpen={isSupportOpen}
        onClose={() => setIsSupportOpen(false)}
        onSuccess={() => setSupportRefreshKey((k) => k + 1)}
        userEmail={user?.email}
      />

    </div>
  );
}

export default SettingsView;
