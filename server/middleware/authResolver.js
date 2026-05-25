/**
 * Auth Resolver — picks the correct auth middleware based on environment.
 *
 * If COGNITO_USER_POOL_ID and COGNITO_CLIENT_ID are set, uses Cognito JWT verification.
 * Otherwise, falls back to local JWT auth (bcrypt + jsonwebtoken).
 */

const { cognitoAuthMiddleware, optionalCognitoAuth } = require('./cognitoAuth');
const { localAuthMiddleware, optionalLocalAuth } = require('./localAuth');

function isCognitoConfigured() {
  return !!(process.env.COGNITO_USER_POOL_ID && process.env.COGNITO_CLIENT_ID);
}

/**
 * Required auth middleware — returns 401 if no valid token.
 */
const authMiddleware = (req, res, next) => {
  if (isCognitoConfigured()) {
    return cognitoAuthMiddleware(req, res, next);
  }
  return localAuthMiddleware(req, res, next);
};

/**
 * Optional auth middleware — sets req.user to null if no token.
 */
const optionalAuth = (req, res, next) => {
  if (isCognitoConfigured()) {
    return optionalCognitoAuth(req, res, next);
  }
  return optionalLocalAuth(req, res, next);
};

module.exports = { authMiddleware, optionalAuth, isCognitoConfigured };
