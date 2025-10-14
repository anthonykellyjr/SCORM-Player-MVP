// API configuration and utilities
const API_URL = window.location.hostname === 'localhost' 
    ? 'http://localhost:3000' 
    : 'https://dev.orthoskool.com';

// Token management
const TokenManager = {
    getAccessToken: () => localStorage.getItem('accessToken'),
    getRefreshToken: () => localStorage.getItem('refreshToken'),
    setTokens: (access, refresh) => {
        localStorage.setItem('accessToken', access);
        localStorage.setItem('refreshToken', refresh);
    },
    clearTokens: () => {
        localStorage.removeItem('accessToken');
        localStorage.removeItem('refreshToken');
        localStorage.removeItem('user');
    }
};

// API request wrapper with auto-refresh
async function apiRequest(endpoint, options = {}) {
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${TokenManager.getAccessToken()}`
        }
    };
    
    const finalOptions = {
        ...defaultOptions,
        ...options,
        headers: { ...defaultOptions.headers, ...options.headers }
    };
    
    let response = await fetch(`${API_URL}${endpoint}`, finalOptions);
    
    // Handle token expiration
    if (response.status === 401) {
        const refreshed = await refreshAccessToken();
        if (refreshed) {
            finalOptions.headers.Authorization = `Bearer ${TokenManager.getAccessToken()}`;
            response = await fetch(`${API_URL}${endpoint}`, finalOptions);
        } else {
            window.location.href = '/login.html';
            return null;
        }
    }
    
    if (!response.ok) {
        throw new Error(`API error: ${response.status}`);
    }
    
    return response.json();
}

async function refreshAccessToken() {
    try {
        const response = await fetch(`${API_URL}/api/auth/refresh`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                refreshToken: TokenManager.getRefreshToken() 
            })
        });
        
        if (response.ok) {
            const data = await response.json();
            TokenManager.setTokens(data.accessToken, data.refreshToken);
            return true;
        }
    } catch (error) {
        console.error('Token refresh failed:', error);
    }
    
    TokenManager.clearTokens();
    return false;
}

// Auth check
function requireAuth(requiredRole = null) {
    const token = TokenManager.getAccessToken();
    const user = JSON.parse(localStorage.getItem('user') || '{}');
    
    if (!token) {
        window.location.href = '/login.html';
        return false;
    }
    
    if (requiredRole && user.role !== requiredRole) {
        alert(`Access denied. ${requiredRole} privileges required.`);
        window.location.href = '/';
        return false;
    }
    
    return true;
}
