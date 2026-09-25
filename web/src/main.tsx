import React from 'react';
import ReactDOM from 'react-dom/client';
import { App } from './App';
import './index.css';
import './ky-ui/tokens.css';
import './ky-ui/navigation.css';
import { applyTheme, storedTheme } from './theme';

applyTheme(storedTheme());

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
