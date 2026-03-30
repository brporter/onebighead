import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { RouterProvider } from 'react-router-dom';
import './styles/index.css';
import { router } from './router';
import { DataProvider } from './contexts/DataContext';
import { UserProvider } from './contexts/UserContext';
import { ToastProvider } from './contexts/ToastContext';
import { PublishProvider } from './contexts/PublishContext';
import { ToastContainer } from './components/common';
import { PublishApp } from './components/common/PublishApp';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <UserProvider>
      <DataProvider>
        <ToastProvider>
          <PublishProvider>
            <RouterProvider router={router} />
            <PublishApp />
            <ToastContainer />
          </PublishProvider>
        </ToastProvider>
      </DataProvider>
    </UserProvider>
  </StrictMode>,
);


