import { useEffect, useState } from 'react';
import { Outlet, useNavigate, useLocation } from 'react-router-dom';
import './styles/App.css';
import { useData } from './DataContext';
import { useUser } from './UserContext';
import UserButton from './UserButton';
import { SupportModal } from './SupportModal';
import { UnreadSupportBanner } from './UnreadSupportBanner';

function App() {
  const {
    collections,
    collectionsLoading,
    loadCollections,
    currentCollection,
  } = useData();

  const { user } = useUser();
  const [isSupportOpen, setIsSupportOpen] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();

  // Load collections on mount
  useEffect(() => {
    loadCollections();
  }, [loadCollections]);

  function handleBackToCollections() {
    navigate('/collections');
  }

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
      <header className="app__header">
        <div className="app__headerContent">
          <div>
            {!isCollectionsList && collections.length > 1 && (
              <button className="app__collectionBack" onClick={handleBackToCollections}>
                ← All Collections
              </button>
            )}
            <h1>{isCollectionsList ? 'Collections' : collectionName}</h1>
            <p className="app__subtitle">
              {isCollectionsList 
                ? 'Select a collection to view its items' 
                : 'Browse categories, then view items and details.'}
            </p>
          </div>
          <div className="app__headerActions">
            <button className="support-link" onClick={handleOpenSupport}>
              <span className="support-link__icon">?</span>
              Support
            </button>
            <UserButton />
          </div>
        </div>
      </header>

      {isCollectionsList ? (
        <main className="app__content app__content--full">
          <Outlet />
        </main>
      ) : (
        <Outlet />
      )}

      <SupportModal
        isOpen={isSupportOpen}
        onClose={handleCloseSupport}
        userEmail={user?.email}
      />
    </div>
  );
}

export default App;

