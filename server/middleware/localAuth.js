const jwt = require('jsonwebtoken');

/**
 * Local JWT Authentication Middleware
 * Used when Cognito is not configured (local development).
 * Validates self-signed JWTs and attaches user info to req.user.
 */

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';

/**
 * Extract Bearer token from Authorization header.
 */
function extractBearerToken(req) {
  const authHeader = req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  const token = authHeader.substring(7);
  return token || null;
}

/**
 * Sign a local JWT for a user.
 */
function signLocalToken(user) {
  const payload = {
    sub: String(user.id),
    email: user.email,
    firstName: user.first_name || null,
    lastName: user.last_name || null,
  };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

/**
 * Required local auth middleware.
 * Verifies a self-signed JWT and attaches req.user = { cognitoSub, email, userId }.
 * Uses the same req.user shape as cognitoAuthMiddleware for compatibility.
 */
const localAuthMiddleware = async (req, res, next) => {
  const token = extractBearerToken(req);

  if (!token) {
    return res.status(401).json({
      error: 'Access denied. No token provided.',
      code: 'NO_TOKEN',
    });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const db = req.app.locals.db;

    // Look up user to confirm they still exist
    const result = await db.query(
      'SELECT id, email, cognito_sub FROM users WHERE id = $1 AND deleted_at IS NULL',
      [payload.sub]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: 'User not found.',
        code: 'INVALID_TOKEN',
      });
    }

    const row = result.rows[0];
    req.user = {
      cognitoSub: row.cognito_sub || `local-${row.id}`,
      email: row.email,
      userId: row.id,
    };
    next();
  } catch (err) {
    const code = err.name === 'TokenExpiredError' ? 'TOKEN_EXPIRED' : 'INVALID_TOKEN';
    const message = code === 'TOKEN_EXPIRED'
      ? 'Token expired. Please login again.'
      : 'Invalid token. Please login again.';
    return res.status(401).json({ error: message, code });
  }
};

/**
 * Optional local auth middleware.
 * Same as localAuthMiddleware but does not fail when no token is present.
 */
const optionalLocalAuth = async (req, res, next) => {
  const token = extractBearerToken(req);

  if (!token) {
    req.user = null;
    return next();
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const db = req.app.locals.db;

    const result = await db.query(
      'SELECT id, email, cognito_sub FROM users WHERE id = $1 AND deleted_at IS NULL',
      [payload.sub]
    );

    if (result.rows.length > 0) {
      const row = result.rows[0];
      req.user = {
        cognitoSub: row.cognito_sub || `local-${row.id}`,
        email: row.email,
        userId: row.id,
      };
    } else {
      req.user = null;
    }
  } catch {
    req.user = null;
  }

  next();
};

module.exports = {
  localAuthMiddleware,
  optionalLocalAuth,
  signLocalToken,
};
