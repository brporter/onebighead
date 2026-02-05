import { useEffect, useState } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import './styles/App.css';
import { useData } from './contexts/DataContext';
import { useUser } from './contexts/UserContext';
import UserButton from './components/user/UserButton';
import { SupportModal } from './components/support/SupportModal';
import { UnreadSupportBanner } from './components/support/UnreadSupportBanner';
import { SiteHeader, SiteFooter } from './components/common';

function App() {
  const {
    collections,
    collectionsLoading,
    loadCollections,
    currentCollection,
  } = useData();

  const { user } = useUser();
  const [isSupportOpen, setIsSupportOpen] = useState(false);
  const location = useLocation();

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
  console.log('[App] Render state:', {
    collectionsLoading,
    collectionsLength: collections.length,
    showLoading: collectionsLoading && collections.length === 0
  });
  if (collectionsLoading && collections.length === 0) {
    return (
      <div className="app">
        <div className="app__loading">Loading...</div>
      </div>
    );
  }

  // Determine header content based on route - show "Collections" when on collections list or no current collection
  const isCollectionsList = !currentCollection && (location.pathname === '/collections' || location.pathname === '/' || location.pathname.startsWith('/collections'));
  const collectionName = currentCollection?.name ?? 'Collection';

  // Determine mobile view state based on route
  const pathParts = location.pathname.split('/').filter(Boolean);
  let mobileView: 'categories' | 'items' | 'detail' | 'settings' | undefined;
  if (pathParts.includes('items')) {
    mobileView = 'detail';
  } else if (pathParts.includes('categories') && pathParts.length >= 4) {
    // /collections/:id/categories/:categoryId - show items
    mobileView = 'items';
  }

  return (
    <div className="app" data-view={mobileView}>
      <UnreadSupportBanner />
      <SiteHeader
        title={isCollectionsList ? 'Collections' : undefined}
        subtitle={isCollectionsList ? 'Select a collection to view its items' : undefined}
      >
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
    </div>
  );
}

export default App;

