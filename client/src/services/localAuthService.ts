/**
 * Local auth service — used when Cognito is not configured.
 * Stores JWT in memory (same pattern as cognitoService).
 */

import { apiClient } from './api';

export interface LocalAuthTokens {
  token: string;
  expiresIn: string;
  expiresAt: number;
}

export interface LocalUser {
  id: number;
  email: string;
  firstName?: string;
  lastName?: string;
}

interface AuthResponse {
  data: {
    message: string;
    user: LocalUser;
    token: string;
    expiresIn: string;
  };
}

// In-memory token store
let currentToken: LocalAuthTokens | null = null;

function parseExpiresIn(expiresIn: string): number {
  // Parse strings like "24h", "7d", "60m"
  const match = expiresIn.match(/^(\d+)([hmd])$/);
  if (!match) return 24 * 60 * 60 * 1000; // default 24h
  const value = parseInt(match[1], 10);
  switch (match[2]) {
    case 'h': return value * 60 * 60 * 1000;
    case 'm': return value * 60 * 1000;
    case 'd': return value * 24 * 60 * 60 * 1000;
    default: return 24 * 60 * 60 * 1000;
  }
}

function storeToken(token: string, expiresIn: string): LocalAuthTokens {
  const tokens: LocalAuthTokens = {
    token,
    expiresIn,
    expiresAt: Date.now() + parseExpiresIn(expiresIn),
  };
  currentToken = tokens;
  // Persist to localStorage for tab survival
  try {
    localStorage.setItem('local_auth_token', JSON.stringify(tokens));
  } catch { /* ignore */ }
  return tokens;
}

function tryRestore(): void {
  if (currentToken) return;
  try {
    const stored = localStorage.getItem('local_auth_token');
    if (stored) {
      const parsed = JSON.parse(stored) as LocalAuthTokens;
      if (parsed.expiresAt > Date.now()) {
        currentToken = parsed;
      } else {
        localStorage.removeItem('local_auth_token');
      }
    }
  } catch { /* ignore */ }
}

// Restore on module load
tryRestore();

export const localAuthService = {
  async login(email: string, password: string): Promise<{ user: LocalUser; tokens: LocalAuthTokens }> {
    const response = await apiClient.post<AuthResponse['data']>('/auth/login', { email, password });
    const { user, token, expiresIn } = response.data;
    const tokens = storeToken(token, expiresIn);
    return { user, tokens };
  },

  async register(
    email: string,
    password: string,
    firstName?: string,
    lastName?: string
  ): Promise<{ user: LocalUser; tokens: LocalAuthTokens }> {
    const response = await apiClient.post<AuthResponse['data']>('/auth/register', {
      email,
      password,
      firstName,
      lastName,
    });
    const { user, token, expiresIn } = response.data;
    const tokens = storeToken(token, expiresIn);
    return { user, tokens };
  },

  async refresh(): Promise<LocalAuthTokens> {
    const response = await apiClient.post<{ token: string; expiresIn: string }>('/auth/refresh');
    const { token, expiresIn } = response.data;
    return storeToken(token, expiresIn);
  },

  signOut(): void {
    currentToken = null;
    try {
      localStorage.removeItem('local_auth_token');
    } catch { /* ignore */ }
  },

  getCurrentToken(): string | null {
    tryRestore();
    if (currentToken && currentToken.expiresAt > Date.now()) {
      return currentToken.token;
    }
    return null;
  },

  getSession(): LocalAuthTokens | null {
    tryRestore();
    if (currentToken && currentToken.expiresAt > Date.now()) {
      return currentToken;
    }
    return null;
  },

  isAuthenticated(): boolean {
    return !!this.getCurrentToken();
  },
};
