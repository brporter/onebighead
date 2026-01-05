import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import './styles/index.css';
import App from './App';
import { DataProvider } from './DataContext';
import Landing from './pages/Landing';
import About from './pages/About';
import Privacy from './pages/Privacy';
import SignUp from './pages/SignUp';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/about" element={<About />} />
        <Route path="/privacy" element={<Privacy />} />
        <Route path="/signup" element={<SignUp />} />
        <Route
          path="/collections/*"
          element={
            <DataProvider>
              <App />
            </DataProvider>
          }
        />
      </Routes>
    </BrowserRouter>
  </StrictMode>,
);

