const express = require('express');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const xss = require('xss');
const { isCognitoConfigured, authMiddleware } = require('../middleware/authResolver');
const { signLocalToken } = require('../middleware/localAuth');
const { logAuditEvent } = require('../utils/auditLogger');
const { sendSuccess, sendError } = require('../utils/responseHelper');

const router = express.Router();

// Input sanitization function
const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  return xss(input.trim());
};

// ============================================================================
// Local auth endpoints (only active when Cognito is NOT configured)
// ============================================================================

/**
 * POST /login — Authenticate with email + password (local mode only)
 */
router.post('/login', [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email address'),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters'),
], async (req, res) => {
  if (isCognitoConfigured()) {
    return sendError(res, 'NOT_AVAILABLE', 'Local auth is disabled when Cognito is configured. Use Cognito to authenticate.', 400);
  }

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return sendError(res, 'VALIDATION_FAILED', errors.array()[0].msg, 400);
  }

  const { email, password } = req.body;
  const sanitizedEmail = sanitizeInput(email);
  const db = req.app.locals.db;

  try {
    const result = await db.query(
      'SELECT id, email, password_hash, first_name, last_name FROM users WHERE email = $1 AND deleted_at IS NULL',
      [sanitizedEmail]
    );

    if (result.rows.length === 0) {
      return sendError(res, 'INVALID_CREDENTIALS', 'Invalid email or password', 401);
    }

    const user = result.rows[0];

    // Check password (reject cognito-managed placeholder)
    if (!user.password_hash || user.password_hash === 'cognito-managed') {
      return sendError(res, 'INVALID_CREDENTIALS', 'Invalid email or password', 401);
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return sendError(res, 'INVALID_CREDENTIALS', 'Invalid email or password', 401);
    }

    const token = signLocalToken(user);

    await logAuditEvent(db, {
      eventType: 'LOGIN_SUCCESS',
      userIdentifier: sanitizedEmail,
      ipAddress: req.ip,
      details: { method: 'local', userAgent: req.get('User-Agent') || null },
      requestId: req.requestId || null,
    });

    sendSuccess(res, {
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
      },
      token,
      expiresIn: process.env.JWT_EXPIRES_IN || '24h',
    });
  } catch (error) {
    console.error('Local login error:', error);
    sendError(res, 'INTERNAL_ERROR', 'Internal server error', 500);
  }
});

/**
 * POST /register — Create account with email + password (local mode only)
 * In local mode, email verification is skipped — users are active immediately.
 */
router.post('/register', [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email address'),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters')
    .matches(/[a-z]/).withMessage('Password must contain a lowercase letter')
    .matches(/[A-Z]/).withMessage('Password must contain an uppercase letter')
    .matches(/\d/).withMessage('Password must contain a number'),
  body('firstName')
    .optional()
    .isLength({ max: 100 })
    .withMessage('First name must be 100 characters or less'),
  body('lastName')
    .optional()
    .isLength({ max: 100 })
    .withMessage('Last name must be 100 characters or less'),
], async (req, res) => {
  if (isCognitoConfigured()) {
    return sendError(res, 'NOT_AVAILABLE', 'Local auth is disabled when Cognito is configured. Use Cognito to register.', 400);
  }

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return sendError(res, 'VALIDATION_FAILED', errors.array()[0].msg, 400);
  }

  const { email, password, firstName, lastName } = req.body;
  const sanitizedEmail = sanitizeInput(email);
  const db = req.app.locals.db;

  try {
    // Check if user already exists
    const existing = await db.query(
      'SELECT id FROM users WHERE email = $1 AND deleted_at IS NULL',
      [sanitizedEmail]
    );

    if (existing.rows.length > 0) {
      return sendError(res, 'EMAIL_EXISTS', 'An account with this email already exists', 409);
    }

    // Hash password
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // Create user
    const result = await db.query(
      `INSERT INTO users (email, password_hash, first_name, last_name)
       VALUES ($1, $2, $3, $4)
       RETURNING id, email, first_name, last_name, created_at`,
      [sanitizedEmail, passwordHash, firstName || null, lastName || null]
    );

    const user = result.rows[0];
    const token = signLocalToken(user);

    await logAuditEvent(db, {
      eventType: 'REGISTER',
      userIdentifier: sanitizedEmail,
      ipAddress: req.ip,
      details: { method: 'local', userAgent: req.get('User-Agent') || null },
      requestId: req.requestId || null,
    });

    sendSuccess(res, {
      message: 'Registration successful',
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
      },
      token,
      expiresIn: process.env.JWT_EXPIRES_IN || '24h',
    }, 201);
  } catch (error) {
    console.error('Local register error:', error);
    sendError(res, 'INTERNAL_ERROR', 'Internal server error', 500);
  }
});

/**
 * POST /refresh — Refresh a local JWT (local mode only)
 * Accepts the current (still valid) token and returns a fresh one.
 */
router.post('/refresh', authMiddleware, async (req, res) => {
  if (isCognitoConfigured()) {
    return sendError(res, 'NOT_AVAILABLE', 'Use Cognito to refresh tokens.', 400);
  }

  try {
    const db = req.app.locals.db;
    const result = await db.query(
      'SELECT id, email, first_name, last_name FROM users WHERE id = $1 AND deleted_at IS NULL',
      [req.user.userId]
    );

    if (result.rows.length === 0) {
      return sendError(res, 'USER_NOT_FOUND', 'User not found', 404);
    }

    const user = result.rows[0];
    const token = signLocalToken(user);

    sendSuccess(res, {
      message: 'Token refreshed',
      token,
      expiresIn: process.env.JWT_EXPIRES_IN || '24h',
    });
  } catch (error) {
    console.error('Token refresh error:', error);
    sendError(res, 'INTERNAL_ERROR', 'Internal server error', 500);
  }
});

/**
 * GET /mode — Returns the current auth mode so the client knows which flow to use.
 */
router.get('/mode', (req, res) => {
  sendSuccess(res, {
    mode: isCognitoConfigured() ? 'cognito' : 'local',
  });
});

// ============================================================================
// Shared endpoints (work in both modes)
// ============================================================================

/**
 * GET /me — Get current user info (protected by auth middleware)
 * Validates: Requirements 1.2, 1.4
 */
router.get('/me', authMiddleware, async (req, res) => {
  try {
    const db = req.app.locals.db;

    const result = await db.query(
      'SELECT id, email, first_name, last_name, created_at FROM users WHERE id = $1 AND deleted_at IS NULL',
      [req.user.userId]
    );

    if (result.rows.length === 0) {
      return sendError(res, 'USER_NOT_FOUND', 'User not found', 404);
    }

    const user = result.rows[0];

    sendSuccess(res, {
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        createdAt: user.created_at
      }
    });
  } catch (error) {
    console.error('Get user info error:', error);
    sendError(res, 'INTERNAL_ERROR', 'Internal server error', 500);
  }
});

/**
 * POST /audit/login — Log a login event (success or failure)
 * Called by the client after Cognito authentication completes.
 * Validates: Requirements 10.1, 10.2, 10.3
 */
router.post('/audit/login', [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email address'),
  body('success')
    .isBoolean()
    .withMessage('success must be a boolean'),
  body('reason')
    .optional()
    .isString()
    .isLength({ max: 500 })
    .withMessage('reason must be a string up to 500 characters')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return sendError(res, 'VALIDATION_FAILED', 'Validation failed', 400);
    }

    const { email, success, reason } = req.body;
    const sanitizedEmail = sanitizeInput(email);
    const db = req.app.locals.db;

    await logAuditEvent(db, {
      eventType: success ? 'LOGIN_SUCCESS' : 'LOGIN_FAILURE',
      userIdentifier: sanitizedEmail,
      ipAddress: req.ip,
      details: {
        reason: reason || null,
        userAgent: req.get('User-Agent') || null,
      },
      requestId: req.requestId || null,
    });

    sendSuccess(res, { message: 'Audit event logged' });
  } catch (error) {
    console.error('Audit login error:', error);
    sendError(res, 'INTERNAL_ERROR', 'Internal server error', 500);
  }
});

/**
 * POST /audit/register — Log a registration event
 * Called by the client after Cognito sign-up completes.
 * Validates: Requirements 10.1, 10.2, 10.3
 */
router.post('/audit/register', [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email address')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return sendError(res, 'VALIDATION_FAILED', 'Validation failed', 400);
    }

    const { email } = req.body;
    const sanitizedEmail = sanitizeInput(email);
    const db = req.app.locals.db;

    await logAuditEvent(db, {
      eventType: 'REGISTER',
      userIdentifier: sanitizedEmail,
      ipAddress: req.ip,
      details: {
        userAgent: req.get('User-Agent') || null,
      },
      requestId: req.requestId || null,
    });

    sendSuccess(res, { message: 'Audit event logged' });
  } catch (error) {
    console.error('Audit register error:', error);
    sendError(res, 'INTERNAL_ERROR', 'Internal server error', 500);
  }
});

/**
 * POST /audit/password-reset — Log a password reset event
 * Called by the client after Cognito password reset flow.
 * Validates: Requirements 10.1, 10.2, 10.3
 */
router.post('/audit/password-reset', [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email address'),
  body('phase')
    .isIn(['request', 'complete'])
    .withMessage('phase must be "request" or "complete"')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return sendError(res, 'VALIDATION_FAILED', 'Validation failed', 400);
    }

    const { email, phase } = req.body;
    const sanitizedEmail = sanitizeInput(email);
    const db = req.app.locals.db;

    const eventType = phase === 'complete'
      ? 'PASSWORD_RESET_COMPLETE'
      : 'PASSWORD_RESET_REQUEST';

    await logAuditEvent(db, {
      eventType,
      userIdentifier: sanitizedEmail,
      ipAddress: req.ip,
      details: {
        phase,
        userAgent: req.get('User-Agent') || null,
      },
      requestId: req.requestId || null,
    });

    sendSuccess(res, { message: 'Audit event logged' });
  } catch (error) {
    console.error('Audit password-reset error:', error);
    sendError(res, 'INTERNAL_ERROR', 'Internal server error', 500);
  }
});

module.exports = router;
