import { createBrowserRouter, Navigate } from 'react-router-dom';
import { lazy, Suspense } from 'react';
import App from './App';
import RequireAuth from './components/common/RequireAuth';
import { NoWorkspaceHandler } from './components/common';

// Lazy load route components for better initial load performance
const CollectionView = lazy(() => import('./views/CollectionView'));
const CategoryView = lazy(() => import('./views/CategoryView'));
const ItemView = lazy(() => import('./views/ItemView'));
const SetupView = lazy(() => import('./views/SetupView'));
const SettingsView = lazy(() => import('./views/SettingsView'));
const SystemAdmin = lazy(() => import('./views/SystemAdmin'));
const WorkspaceCreationView = lazy(() => import('./views/WorkspaceCreationView'));
const TermsView = lazy(() => import('./views/TermsView'));
const WelcomeView = lazy(() => import('./views/WelcomeView'));

// Loading fallback component
const LoadingFallback = () => (
  <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%', padding: '2rem' }}>
    Loading...
  </div>
);

export const router = createBrowserRouter([
  {
    path: '/',
    element: (
      <RequireAuth>
        <NoWorkspaceHandler>
          <App />
        </NoWorkspaceHandler>
      </RequireAuth>
    ),
    children: [
      {
        index: true,
        element: <Navigate to="/collections" replace />,
      },
      {
        path: 'collections',
        element: (
          <Suspense fallback={<LoadingFallback />}>
            <CollectionView />
          </Suspense>
        ),
      },
      {
        path: 'collections/:collectionId',
        element: (
          <Suspense fallback={<LoadingFallback />}>
            <CategoryView />
          </Suspense>
        ),
      },
      {
        path: 'collections/:collectionId/categories/:categoryId',
        element: (
          <Suspense fallback={<LoadingFallback />}>
            <CategoryView />
          </Suspense>
        ),
      },
      {
        path: 'collections/:collectionId/items/:itemId',
        element: (
          <Suspense fallback={<LoadingFallback />}>
            <ItemView />
          </Suspense>
        ),
      },
    ],
  },
  {
    path: '/setup',
    element: (
      <RequireAuth>
        <Suspense fallback={<LoadingFallback />}>
          <SetupView />
        </Suspense>
      </RequireAuth>
    ),
  },
  {
    path: '/settings',
    element: (
      <RequireAuth>
        <Suspense fallback={<LoadingFallback />}>
          <SettingsView />
        </Suspense>
      </RequireAuth>
    ),
  },
  {
    path: '/admin',
    element: (
      <RequireAuth>
        <Suspense fallback={<LoadingFallback />}>
          <SystemAdmin />
        </Suspense>
      </RequireAuth>
    ),
  },
  {
    path: '/welcome',
    element: (
      <RequireAuth skipWelcomeCheck skipTermsCheck>
        <Suspense fallback={<LoadingFallback />}>
          <WelcomeView />
        </Suspense>
      </RequireAuth>
    ),
  },
  {
    path: '/terms',
    element: (
      <RequireAuth skipTermsCheck>
        <Suspense fallback={<LoadingFallback />}>
          <TermsView />
        </Suspense>
      </RequireAuth>
    ),
  },
  {
    path: '/workspaces/new',
    element: (
      <RequireAuth skipWelcomeCheck>
        <Suspense fallback={<LoadingFallback />}>
          <WorkspaceCreationView />
        </Suspense>
      </RequireAuth>
    ),
  },
]);
