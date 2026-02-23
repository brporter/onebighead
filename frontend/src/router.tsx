import { createBrowserRouter, Navigate } from 'react-router-dom';
import { lazy, Suspense } from 'react';
import App from './App';
import RequireAuth from './components/common/RequireAuth';
import LoadingFallback from './components/common/LoadingFallback';
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
const PublicLayout = lazy(() => import('./components/public/PublicLayout'));
const PublicCollectionsView = lazy(() => import('./views/PublicCollectionsView'));
const PublicCollectionDetailView = lazy(() => import('./views/PublicCollectionDetailView'));
const PublicItemView = lazy(() => import('./views/PublicItemView'));

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
  {
    path: '/public/:slug',
    element: (
      <Suspense fallback={<LoadingFallback />}>
        <PublicLayout />
      </Suspense>
    ),
    children: [
      {
        index: true,
        element: (
          <Suspense fallback={<LoadingFallback />}>
            <PublicCollectionsView />
          </Suspense>
        ),
      },
      {
        path: 'collections/:collectionId',
        element: (
          <Suspense fallback={<LoadingFallback />}>
            <PublicCollectionDetailView />
          </Suspense>
        ),
      },
      {
        path: 'items/:itemId',
        element: (
          <Suspense fallback={<LoadingFallback />}>
            <PublicItemView />
          </Suspense>
        ),
      },
    ],
  },
]);
