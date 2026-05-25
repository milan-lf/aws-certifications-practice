require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

// Import routes
const authRoutes = require('./routes/auth');
const testRoutes = require('./routes/tests');
const progressRoutes = require('./routes/progress');
const usersRoutes = require('./routes/users');
const bookmarksRoutes = require('./routes/bookmarks');
const adminRoutes = require('./routes/admin');

// Initialize cache service
const cacheService = require('./utils/cacheService');
cacheService.init();

// Import middleware
const { authMiddleware, isCognitoConfigured } = require('./middleware/authResolver');
const errorHandler = require('./middleware/errorHandler');
const requestIdMiddleware = require('./middleware/requestId');
const cookieParser = require('cookie-parser');
const { csrfTokenHandler, doubleCsrfProtection } = require('./middleware/csrf');
const cspNonceMiddleware = require('./middleware/cspNonce');

const app = express();
const PORT = process.env.PORT || 5000;

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DB_SSL === 'true' ? {
    rejectUnauthorized: false
  } : false
});

// Test database connection and seed data if empty
const { seedIfEmpty } = require('./database/seedOnStart');
pool.connect((err, client, release) => {
  if (err) {
    console.error('Error connecting to database:', err);
    process.exit(1);
  } else {
    console.log('Connected to PostgreSQL database');
    release();
    // Seed test data on first run (non-blocking)
    seedIfEmpty(pool).catch((e) => console.error('Seed error:', e.message));
  }
});

// Make pool available to routes
app.locals.db = pool;

// Generate CSP nonce per request (must run before Helmet)
// Validates: Requirements 8.1, 8.2, 8.3
app.use(cspNonceMiddleware);

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", (req, res) => `'nonce-${res.locals.cspNonce}'`],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false
}));

// CORS configuration
const corsOptions = {
  origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  credentials: true,
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

const { RATE_LIMIT_GENERAL } = require('./utils/constants');

const enableRateLimit = process.env.ENABLE_RATE_LIMIT === 'true';

// Rate limiting — toggled via ENABLE_RATE_LIMIT env var
if (enableRateLimit) {
  const limiter = rateLimit({
    windowMs: RATE_LIMIT_GENERAL.windowMs,
    max: RATE_LIMIT_GENERAL.max,
    message: {
      error: 'Too many requests from this IP, please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false,
  });
  app.use('/api/', limiter);
}

// Endpoint-specific rate limiters for public auth endpoints
// Validates: Requirements 9.1, 9.2, 9.3, 9.4
const { loginLimiter, registerLimiter, forgotPasswordLimiter } = require('./middleware/rateLimiters');
if (enableRateLimit) {
  app.use('/api/auth/login', loginLimiter);
  app.use('/api/auth/register', registerLimiter);
  app.use('/api/auth/forgot-password', forgotPasswordLimiter);
}

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Cookie parser (required by csrf-csrf)
app.use(cookieParser());

// Request ID middleware (after body parser, before routes)
app.use(requestIdMiddleware);

// CSRF token endpoint (before CSRF validation middleware)
app.get('/api/csrf-token', csrfTokenHandler);

// CSRF validation middleware (validates POST, PUT, PATCH, DELETE requests)
app.use(doubleCsrfProtection);

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/tests', testRoutes);
app.use('/api/progress', authMiddleware, progressRoutes);
app.use('/api/users', authMiddleware, usersRoutes);
app.use('/api/bookmarks', authMiddleware, bookmarksRoutes);
app.use('/api/admin', authMiddleware, adminRoutes);

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Route not found',
    path: req.originalUrl
  });
});

// Error handling middleware
app.use(errorHandler);

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  pool.end(() => {
    console.log('Database pool closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  pool.end(() => {
    console.log('Database pool closed');
    process.exit(0);
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`Auth mode: ${isCognitoConfigured() ? 'Cognito' : 'Local (bcrypt + JWT)'}`);
  console.log(`CORS origin: ${process.env.CORS_ORIGIN || 'http://localhost:3000'}`);
});