import { useEffect, useState, useCallback } from 'react';
import { Outlet, useLocation, useNavigate } from 'react-router-dom';
import './styles/App.css';
import { useData } from './contexts/useData';
import { useUser } from './contexts/useUser';
import { usePublish } from './contexts/usePublish';
import { PublishProvider } from './contexts/PublishContext';
import { PublishResolver } from './components/common/PublishResolver';
import UserButton from './components/user/UserButton';
import { SupportModal } from './components/support/SupportModal';
import { UnreadSupportBanner } from './components/support/UnreadSupportBanner';
import { SiteHeader, SiteFooter } from './components/common';

function AppContent() {
  const {
    collections,
    collectionsLoading,
    loadCollections,
    loadCategoriesForCollection,
    currentCollection,
  } = useData();

  const { user } = useUser();
  const { pendingIntent, clearIntent } = usePublish();
  const navigate = useNavigate();
  const [isSupportOpen, setIsSupportOpen] = useState(false);
  const location = useLocation();

  const handlePublishComplete = useCallback(() => {
    loadCollections();
    if (currentCollection) {
      loadCategoriesForCollection(currentCollection.collectionId);
    }
  }, [loadCollections, loadCategoriesForCollection, currentCollection]);

  // Load collections on mount
  useEffect(() => {
    loadCollections();
  }, [loadCollections]);

  function handleOpenSupport() {
    setIsSupportOpen(true);
  }

  function handleCloseSupport() {
    setIsSupportOpen(false);
  }

  // Loading state
  if (collectionsLoading && collections.length === 0) {
    return (
      <div className="app">
        <div className="app__loading">Loading...</div>
      </div>
    );
  }

  // Determine header content based on route - show "Collections" when on collections list or no current collection
  const isCollectionsList = !currentCollection && (location.pathname === '/collections' || location.pathname === '/' || location.pathname.startsWith('/collections'));

  // Determine mobile view state based on route
  const pathParts = location.pathname.split('/').filter(Boolean);
  let mobileView: 'categories' | 'items' | 'detail' | 'settings' | undefined;
  if (pathParts.includes('items')) {
    mobileView = 'detail';
  } else if (pathParts.includes('categories') && pathParts.length >= 4) {
    // /collections/:id/categories/:categoryId - show items
    mobileView = 'items';
  }

  const workspaceSlug = user?.activeWorkspace?.slug;

  return (
    <div className="app" data-view={mobileView}>
      <UnreadSupportBanner />
      <SiteHeader
        title={isCollectionsList ? 'Collections' : undefined}
        subtitle={isCollectionsList ? 'Select a collection to view its items' : undefined}
      >
        {workspaceSlug ? (
          <a
            href={`/public/${workspaceSlug}`}
            target="_blank"
            rel="noopener noreferrer"
            className="gallery-link"
            title="Open your public gallery"
          >
            <svg className="gallery-link__icon" viewBox="0 0 24 24" width="16" height="16" aria-hidden="true">
              <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z" fill="currentColor" />
            </svg>
            Public Gallery
          </a>
        ) : (
          <button
            type="button"
            className="gallery-link gallery-link--setup"
            onClick={() => navigate('/settings?section=workspaces')}
            title="Set up your public gallery"
          >
            Set Up Public Gallery
          </button>
        )}
        <button className="support-link support-link--icon" onClick={handleOpenSupport} title="Support" aria-label="Support">
          <span className="support-link__icon">?</span>
        </button>
        <UserButton />
      </SiteHeader>

      {isCollectionsList ? (
        <main className="app__content app__content--full">
          <Outlet />
        </main>
      ) : (
        <Outlet />
      )}

      <SiteFooter />

      <SupportModal
        isOpen={isSupportOpen}
        onClose={handleCloseSupport}
        userEmail={user?.email}
      />

      <PublishResolver
        intent={pendingIntent}
        onClearIntent={clearIntent}
        onComplete={handlePublishComplete}
      />
    </div>
  );
}

function App() {
  return (
    <PublishProvider>
      <AppContent />
    </PublishProvider>
  );
}

export default App;
