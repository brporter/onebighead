import { useEffect, useState } from 'react';
import { Outlet, useNavigate, useParams, useLocation } from 'react-router-dom';
import './styles/App.css';
import { useData } from './DataContext';
import UserButton from './UserButton';
import Settings from './Settings';
import type { Collection } from './types';

function App() {
  const {
    collections,
    collectionsLoading,
    loadCollections,
    currentCollection,
  } = useData();

  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();

  // Load collections on mount
  useEffect(() => {
    loadCollections();
  }, [loadCollections]);

  function handleBackToCollections() {
    navigate('/collections');
  }

  function handleOpenSettings() {
    setIsSettingsOpen(true);
  }

  function handleCloseSettings() {
    setIsSettingsOpen(false);
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
          <UserButton onClick={handleOpenSettings} />
        </div>
      </header>

      {isCollectionsList ? (
        <main className="app__content app__content--full">
          <Outlet />
        </main>
      ) : (
        <Outlet />
      )}

      <Settings isOpen={isSettingsOpen} onClose={handleCloseSettings} />
    </div>
  );
}

export default App;

