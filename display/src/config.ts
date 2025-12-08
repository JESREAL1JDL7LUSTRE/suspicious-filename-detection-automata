// API configuration for both development and production (Electron)

// Detect if running in Electron
const isElectron = () => {
  // Check if we're running in Electron
  const userAgent = navigator.userAgent.toLowerCase();
  return userAgent.includes('electron');
};

// Detect if running from file:// protocol (Electron production)
const isFileProtocol = () => {
  return window.location.protocol === 'file:';
};

// Get the correct API base URL
export const getApiUrl = (): string => {
  // If running in Electron (file:// protocol), use direct localhost
  if (isFileProtocol() || isElectron()) {
    // In Electron, always use localhost:3001
    return 'http://localhost:3001';
  }
  
  // In development (Vite dev server), use relative URLs (proxy handles it)
  return '';
};

export const API_BASE_URL = getApiUrl();

console.log('API Base URL:', API_BASE_URL);
console.log('Is Electron:', isElectron());
console.log('Is File Protocol:', isFileProtocol());