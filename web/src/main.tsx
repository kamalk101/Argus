import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import './index.css';
import App from './App.tsx';

// The shell uses `useNavigate` and `NavLink`, so the router has to wrap the whole tree. In the
// packaged WebView2 shell the agent serves index.html for any path, so history routing works there
// too; `vite preview` needs `appType: 'spa'` (the default) for the same fallback.
createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </StrictMode>,
);
