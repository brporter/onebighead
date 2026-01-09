import { createBrowserRouter, Navigate } from 'react-router-dom';
import App from './App';
import RequireAuth from './RequireAuth';
import CollectionView from './views/CollectionView';
import CategoryView from './views/CategoryView';
import ItemView from './views/ItemView';

export const router = createBrowserRouter([
  {
    path: '/',
    element: (
      <RequireAuth>
        <App />
      </RequireAuth>
    ),
    children: [
      {
        index: true,
        element: <Navigate to="/collections" replace />,
      },
      {
        path: 'collections',
        element: <CollectionView />,
      },
      {
        path: 'collections/:collectionId',
        element: <CategoryView />,
      },
      {
        path: 'collections/:collectionId/categories/:categoryId',
        element: <CategoryView />,
      },
      {
        path: 'collections/:collectionId/items/:itemId',
        element: <ItemView />,
      },
    ],
  },
]);
