import {
  CognitoUserPool,
  CognitoUser,
  CognitoUserAttribute,
  AuthenticationDetails,
  CognitoUserSession,
  CognitoRefreshToken,
} from 'amazon-cognito-identity-js';

// --- Types ---

export interface AuthTokens {
  accessToken: string;
  idToken: string;
  refreshToken: string;
  expiresAt: number;
}

export interface SignUpResult {
  userConfirmed: boolean;
  userSub: string;
}

// --- In-memory token store ---
// Primary store is in-memory; on init we try to restore from Cognito's
// built-in localStorage session so new tabs / refreshes work.

let currentTokens: AuthTokens | null = null;

// --- User Pool setup ---

const poolData = {
  UserPoolId: process.env.REACT_APP_COGNITO_USER_POOL_ID || '',
  ClientId: process.env.REACT_APP_COGNITO_CLIENT_ID || '',
};

// Only create the pool if Cognito is configured — the SDK throws on empty UserPoolId
const userPool: CognitoUserPool | null =
  poolData.UserPoolId && poolData.ClientId
    ? new CognitoUserPool(poolData)
    : null;

// Try to restore session from Cognito's built-in storage on load
function tryRestoreSession(): void {
  if (!userPool) return;
  try {
    const cognitoUser = userPool.getCurrentUser();
    if (cognitoUser) {
      cognitoUser.getSession((err: Error | null, session: CognitoUserSession | null) => {
        if (!err && session && session.isValid()) {
          currentTokens = extractTokens(session);
        }
      });
    }
  } catch {
    // Ignore — no stored session
  }
}

// --- Helpers ---

function assertPool(): CognitoUserPool {
  if (!userPool) {
    throw new Error('Cognito is not configured. Set REACT_APP_COGNITO_USER_POOL_ID and REACT_APP_COGNITO_CLIENT_ID.');
  }
  return userPool;
}

function getCognitoUser(email: string): CognitoUser {
  return new CognitoUser({ Username: email, Pool: assertPool() });
}

function extractTokens(session: CognitoUserSession): AuthTokens {
  const accessToken = session.getAccessToken().getJwtToken();
  const idToken = session.getIdToken().getJwtToken();
  const refreshToken = session.getRefreshToken().getToken();
  const expiresAt = session.getAccessToken().getExpiration() * 1000; // ms
  return { accessToken, idToken, refreshToken, expiresAt };
}

// Restore session on module load (handles new tabs and page refreshes)
tryRestoreSession();

// --- Service ---

export const cognitoService = {
  /**
   * Register a new user with Cognito.
   */
  signUp(
    email: string,
    password: string,
    firstName?: string,
    lastName?: string
  ): Promise<SignUpResult> {
    return new Promise((resolve, reject) => {
      const attributes: CognitoUserAttribute[] = [
        new CognitoUserAttribute({ Name: 'email', Value: email }),
      ];
      if (firstName) {
        attributes.push(
          new CognitoUserAttribute({ Name: 'given_name', Value: firstName })
        );
      }
      if (lastName) {
        attributes.push(
          new CognitoUserAttribute({ Name: 'family_name', Value: lastName })
        );
      }

      assertPool().signUp(email, password, attributes, [], (err, result) => {
        if (err) {
          return reject(err);
        }
        resolve({
          userConfirmed: result?.userConfirmed ?? false,
          userSub: result?.userSub ?? '',
        });
      });
    });
  },

  /**
   * Confirm sign-up with the verification code sent to the user's email.
   */
  confirmSignUp(email: string, code: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const cognitoUser = getCognitoUser(email);
      cognitoUser.confirmRegistration(code, true, (err) => {
        if (err) {
          return reject(err);
        }
        resolve();
      });
    });
  },

  /**
   * Resend the confirmation code for sign-up verification.
   */
  resendConfirmationCode(email: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const cognitoUser = getCognitoUser(email);
      cognitoUser.resendConfirmationCode((err) => {
        if (err) {
          return reject(err);
        }
        resolve();
      });
    });
  },

  /**
   * Authenticate user and store tokens in memory.
   */
  signIn(email: string, password: string): Promise<AuthTokens> {
    return new Promise((resolve, reject) => {
      const cognitoUser = getCognitoUser(email);
      const authDetails = new AuthenticationDetails({
        Username: email,
        Password: password,
      });

      cognitoUser.authenticateUser(authDetails, {
        onSuccess(session: CognitoUserSession) {
          const tokens = extractTokens(session);
          currentTokens = tokens;
          resolve(tokens);
        },
        onFailure(err) {
          reject(err);
        },
      });
    });
  },

  /**
   * Sign out the current user and clear in-memory tokens.
   */
  signOut(): void {
    if (userPool) {
      const cognitoUser = userPool.getCurrentUser();
      if (cognitoUser) {
        cognitoUser.signOut();
      }
    }
    currentTokens = null;
  },

  /**
   * Initiate the forgot-password flow (sends a code to the user's email).
   */
  forgotPassword(email: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const cognitoUser = getCognitoUser(email);
      cognitoUser.forgotPassword({
        onSuccess() {
          resolve();
        },
        onFailure(err) {
          reject(err);
        },
      });
    });
  },

  /**
   * Confirm a new password using the code from forgotPassword.
   */
  confirmForgotPassword(
    email: string,
    code: string,
    newPassword: string
  ): Promise<void> {
    return new Promise((resolve, reject) => {
      const cognitoUser = getCognitoUser(email);
      cognitoUser.confirmPassword(code, newPassword, {
        onSuccess() {
          resolve();
        },
        onFailure(err) {
          reject(err);
        },
      });
    });
  },

  /**
   * Change the password for the currently authenticated user.
   */
  changePassword(oldPassword: string, newPassword: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const cognitoUser = assertPool().getCurrentUser();
      if (!cognitoUser) {
        return reject(new Error('No authenticated user'));
      }

      // getSession is required before changePassword
      cognitoUser.getSession(
        (sessionErr: Error | null, session: CognitoUserSession | null) => {
          if (sessionErr || !session) {
            return reject(sessionErr || new Error('No active session'));
          }
          cognitoUser.changePassword(oldPassword, newPassword, (err) => {
            if (err) {
              return reject(err);
            }
            resolve();
          });
        }
      );
    });
  },

  /**
   * Refresh the current session using the stored refresh token.
   */
  refreshSession(): Promise<AuthTokens> {
    return new Promise((resolve, reject) => {
      if (!currentTokens) {
        return reject(new Error('No current session to refresh'));
      }

      const cognitoUser = assertPool().getCurrentUser();
      if (!cognitoUser) {
        return reject(new Error('No authenticated user'));
      }

      const refreshToken = new CognitoRefreshToken({
        RefreshToken: currentTokens.refreshToken,
      });

      cognitoUser.refreshSession(
        refreshToken,
        (err: Error | null, session: CognitoUserSession) => {
          if (err) {
            return reject(err);
          }
          const tokens = extractTokens(session);
          currentTokens = tokens;
          resolve(tokens);
        }
      );
    });
  },

  /**
   * Return the current in-memory tokens, or null if not authenticated.
   */
  getCurrentSession(): AuthTokens | null {
    if (!currentTokens) {
      tryRestoreSession();
    }
    return currentTokens;
  },
};
