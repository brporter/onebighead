import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { RouterProvider } from 'react-router-dom';
import './styles/index.css';
import { router } from './router';
import { DataProvider } from './contexts/DataContext';
import { UserProvider } from './contexts/UserContext';
import { ToastProvider } from './contexts/ToastContext';
import { ToastContainer } from './components/common';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <UserProvider>
      <DataProvider>
        <ToastProvider>
          <RouterProvider router={router} />
          <ToastContainer />
        </ToastProvider>
      </DataProvider>
    </UserProvider>
  </StrictMode>,
);


