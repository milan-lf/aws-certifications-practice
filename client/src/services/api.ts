import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse, InternalAxiosRequestConfig } from 'axios';
import { cognitoService } from './cognitoService';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

/**
 * Detect auth mode based on environment variables.
 * If Cognito pool/client IDs are set, use Cognito. Otherwise, local JWT.
 */
export function getAuthMode(): 'cognito' | 'local' {
  const poolId = process.env.REACT_APP_COGNITO_USER_POOL_ID;
  const clientId = process.env.REACT_APP_COGNITO_CLIENT_ID;
  if (poolId && clientId) return 'cognito';
  return 'local';
}

// Create axios instance with base configuration
const api: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000, // 30 seconds
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true, // Required for CSRF cookie
});

// --- CSRF token management ---

let csrfToken: string | null = null;

const MUTATING_METHODS = ['post', 'put', 'patch', 'delete'];

/**
 * Fetch a CSRF token from the server and store it in memory.
 * Also sets the double-submit cookie via the response.
 * Logs a warning on failure but does not throw — some endpoints don't require CSRF.
 */
export async function fetchCsrfToken(): Promise<void> {
  try {
    const response = await axios.get<{ csrfToken: string }>(
      `${API_BASE_URL}/csrf-token`,
      { withCredentials: true }
    );
    csrfToken = response.data.csrfToken;
  } catch (err) {
    console.warn('Failed to fetch CSRF token — mutating requests may be rejected:', err);
  }
}

// Fetch CSRF token on module load (non-blocking)
fetchCsrfToken();

// --- 401 refresh management ---

let isRefreshing = false;
let refreshSubscribers: Array<(token: string) => void> = [];

function subscribeTokenRefresh(cb: (token: string) => void) {
  refreshSubscribers.push(cb);
}

function onTokenRefreshed(token: string) {
  refreshSubscribers.forEach((cb) => cb(token));
  refreshSubscribers = [];
}

function onRefreshFailed() {
  refreshSubscribers = [];
}

// --- Interceptors ---

// Request interceptor — attach auth token + CSRF token
api.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    const mode = getAuthMode();

    if (mode === 'cognito') {
      // Attach Bearer token from Cognito in-memory store
      const session = cognitoService.getCurrentSession();
      if (session) {
        config.headers.Authorization = `Bearer ${session.accessToken}`;
        // Send ID token claims so server can use them for auto-create
        try {
          const payload = JSON.parse(atob(session.idToken.split('.')[1]));
          config.headers['X-User-Email'] = payload.email || '';
          config.headers['X-User-Given-Name'] = payload.given_name || '';
          config.headers['X-User-Family-Name'] = payload.family_name || '';
        } catch { /* ignore */ }
      }
    } else {
      // Local mode — attach JWT from localStorage/memory
      // Import dynamically to avoid circular deps at module load
      const stored = localStorage.getItem('local_auth_token');
      if (stored) {
        try {
          const parsed = JSON.parse(stored);
          if (parsed.token && parsed.expiresAt > Date.now()) {
            config.headers.Authorization = `Bearer ${parsed.token}`;
          }
        } catch { /* ignore */ }
      }
    }

    // Attach CSRF token on mutating requests
    if (csrfToken && config.method && MUTATING_METHODS.includes(config.method.toLowerCase())) {
      config.headers['X-CSRF-Token'] = csrfToken;
    }

    return config;
  },
  (error) => Promise.reject(error)
);


// Response interceptor — handle 401 with one refresh attempt, then logout
api.interceptors.response.use(
  (response: AxiosResponse) => response,
  async (error) => {
    const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean };

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      const mode = getAuthMode();

      if (mode === 'cognito') {
        if (!isRefreshing) {
          isRefreshing = true;
          try {
            const tokens = await cognitoService.refreshSession();
            isRefreshing = false;
            onTokenRefreshed(tokens.accessToken);

            // Retry the original request with the new token
            originalRequest.headers.Authorization = `Bearer ${tokens.accessToken}`;
            return api(originalRequest);
          } catch {
            isRefreshing = false;
            onRefreshFailed();
            window.dispatchEvent(new CustomEvent('auth:logout'));
            return Promise.reject(error);
          }
        }

        // Another request hit 401 while refresh is in-flight — queue it
        return new Promise((resolve) => {
          subscribeTokenRefresh((newToken: string) => {
            originalRequest.headers.Authorization = `Bearer ${newToken}`;
            resolve(api(originalRequest));
          });
        });
      } else {
        // Local mode — try refresh endpoint
        if (!isRefreshing) {
          isRefreshing = true;
          try {
            const response = await axios.post(
              `${API_BASE_URL}/auth/refresh`,
              {},
              {
                headers: { Authorization: originalRequest.headers.Authorization },
                withCredentials: true,
              }
            );
            const { token } = response.data.data || response.data;
            if (token) {
              const stored = localStorage.getItem('local_auth_token');
              const parsed = stored ? JSON.parse(stored) : {};
              parsed.token = token;
              parsed.expiresAt = Date.now() + 24 * 60 * 60 * 1000;
              localStorage.setItem('local_auth_token', JSON.stringify(parsed));

              isRefreshing = false;
              onTokenRefreshed(token);
              originalRequest.headers.Authorization = `Bearer ${token}`;
              return api(originalRequest);
            }
          } catch {
            isRefreshing = false;
            onRefreshFailed();
            window.dispatchEvent(new CustomEvent('auth:logout'));
            return Promise.reject(error);
          }
        }

        return new Promise((resolve) => {
          subscribeTokenRefresh((newToken: string) => {
            originalRequest.headers.Authorization = `Bearer ${newToken}`;
            resolve(api(originalRequest));
          });
        });
      }
    }

    // Handle rate limiting
    if (error.response?.status === 429) {
      console.warn('Rate limit exceeded:', error.response.data?.error);
    }

    // Handle server errors
    if (error.response && error.response.status >= 500) {
      console.error('Server error:', error.response.data?.error);
    }

    if (!error.response && error.request) {
      console.error('Network error:', error.message);
    }

    return Promise.reject(error);
  }
);

// Generic API methods
export const apiClient = {
  get: <T = any>(url: string, config?: AxiosRequestConfig): Promise<AxiosResponse<T>> =>
    api.get(url, config),

  post: <T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<AxiosResponse<T>> =>
    api.post(url, data, config),

  put: <T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<AxiosResponse<T>> =>
    api.put(url, data, config),

  patch: <T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<AxiosResponse<T>> =>
    api.patch(url, data, config),

  delete: <T = any>(url: string, config?: AxiosRequestConfig): Promise<AxiosResponse<T>> =>
    api.delete(url, config),
};

// Error handling utilities
export const handleApiError = (error: any): string => {
  if (error.response?.data?.error) {
    return error.response.data.error;
  } else if (error.request) {
    return 'Network error. Please check your connection and try again.';
  } else {
    return 'An unexpected error occurred. Please try again.';
  }
};

export const isNetworkError = (error: any): boolean => {
  return !error.response && error.request;
};

export const isServerError = (error: any): boolean => {
  return error.response && error.response.status >= 500;
};

export const isClientError = (error: any): boolean => {
  return error.response && error.response.status >= 400 && error.response.status < 500;
};

export default api;
