const express = require('express');
const request = require('supertest');

// Mock cognitoAuthMiddleware — injects req.user when Authorization header present
const mockAuthMiddleware = jest.fn((req, res, next) => {
  const auth = req.header('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token', code: 'NO_TOKEN' });
  }
  req.user = { cognitoSub: 'sub-123', email: 'test@example.com', userId: 42 };
  next();
});

jest.mock('../middleware/authResolver', () => ({
  authMiddleware: (...args) => mockAuthMiddleware(...args),
  isCognitoConfigured: () => true,
}));

jest.mock('../middleware/cognitoAuth', () => ({
  cognitoAuthMiddleware: (...args) => mockAuthMiddleware(...args),
}));

// Mock auditLogger
const mockLogAuditEvent = jest.fn().mockResolvedValue(undefined);
jest.mock('../utils/auditLogger', () => ({
  logAuditEvent: (...args) => mockLogAuditEvent(...args),
}));

function createMockDb(overrides = {}) {
  const userRow = overrides.userRow !== undefined ? overrides.userRow : {
    id: 42,
    email: 'test@example.com',
    first_name: 'Test',
    last_name: 'User',
    created_at: '2024-01-01',
  };

  return {
    query: jest.fn(async () => ({
      rows: userRow ? [userRow] : [],
    })),
  };
}

function buildApp(db) {
  const app = express();
  app.use(express.json());
  app.locals.db = db;
  app.use('/api/auth', require('./auth'));
  return app;
}

beforeEach(() => {
  jest.clearAllMocks();
});

// --- GET /me ---
describe('GET /api/auth/me', () => {
  test('returns user info when authenticated', async () => {
    const db = createMockDb();
    const app = buildApp(db);

    const res = await request(app)
      .get('/api/auth/me')
      .set('Authorization', 'Bearer valid-token');

    expect(res.status).toBe(200);
    expect(res.body.data.user).toEqual({
      id: 42,
      email: 'test@example.com',
      firstName: 'Test',
      lastName: 'User',
      createdAt: '2024-01-01',
    });
    // Should query with userId from req.user
    expect(db.query).toHaveBeenCalledWith(
      expect.stringContaining('WHERE id = $1 AND deleted_at IS NULL'),
      [42]
    );
  });

  test('returns 401 without token', async () => {
    const db = createMockDb();
    const app = buildApp(db);

    const res = await request(app).get('/api/auth/me');
    expect(res.status).toBe(401);
  });

  test('returns 404 when user not found in DB', async () => {
    const db = createMockDb({ userRow: null });
    const app = buildApp(db);

    const res = await request(app)
      .get('/api/auth/me')
      .set('Authorization', 'Bearer valid-token');

    expect(res.status).toBe(404);
    expect(res.body.error.message).toBe('User not found');
  });
});

// --- POST /audit/login ---
describe('POST /api/auth/audit/login', () => {
  test('logs LOGIN_SUCCESS audit event', async () => {
    const db = createMockDb();
    const app = buildApp(db);

    const res = await request(app)
      .post('/api/auth/audit/login')
      .send({ email: 'user@example.com', success: true });

    expect(res.status).toBe(200);
    expect(res.body.data.message).toBe('Audit event logged');
    expect(mockLogAuditEvent).toHaveBeenCalledWith(db, expect.objectContaining({
      eventType: 'LOGIN_SUCCESS',
      userIdentifier: 'user@example.com',
    }));
  });

  test('logs LOGIN_FAILURE audit event', async () => {
    const db = createMockDb();
    const app = buildApp(db);

    const res = await request(app)
      .post('/api/auth/audit/login')
      .send({ email: 'user@example.com', success: false, reason: 'Bad password' });

    expect(res.status).toBe(200);
    expect(mockLogAuditEvent).toHaveBeenCalledWith(db, expect.objectContaining({
      eventType: 'LOGIN_FAILURE',
      details: expect.objectContaining({ reason: 'Bad password' }),
    }));
  });

  test('returns 400 for invalid email', async () => {
    const db = createMockDb();
    const app = buildApp(db);

    const res = await request(app)
      .post('/api/auth/audit/login')
      .send({ email: 'not-an-email', success: true });

    expect(res.status).toBe(400);
    expect(res.body.error.message).toBe('Validation failed');
  });

  test('returns 400 when success field is missing', async () => {
    const db = createMockDb();
    const app = buildApp(db);

    const res = await request(app)
      .post('/api/auth/audit/login')
      .send({ email: 'user@example.com' });

    expect(res.status).toBe(400);
  });
});

// --- POST /audit/register ---
describe('POST /api/auth/audit/register', () => {
  test('logs REGISTER audit event', async () => {
    const db = createMockDb();
    const app = buildApp(db);

    const res = await request(app)
      .post('/api/auth/audit/register')
      .send({ email: 'new@example.com' });

    expect(res.status).toBe(200);
    expect(mockLogAuditEvent).toHaveBeenCalledWith(db, expect.objectContaining({
      eventType: 'REGISTER',
      userIdentifier: 'new@example.com',
    }));
  });

  test('returns 400 for invalid email', async () => {
    const db = createMockDb();
    const app = buildApp(db);

    const res = await request(app)
      .post('/api/auth/audit/register')
      .send({ email: 'bad' });

    expect(res.status).toBe(400);
  });
});

// --- POST /audit/password-reset ---
describe('POST /api/auth/audit/password-reset', () => {
  test('logs PASSWORD_RESET_REQUEST for request phase', async () => {
    const db = createMockDb();
    const app = buildApp(db);

    const res = await request(app)
      .post('/api/auth/audit/password-reset')
      .send({ email: 'user@example.com', phase: 'request' });

    expect(res.status).toBe(200);
    expect(mockLogAuditEvent).toHaveBeenCalledWith(db, expect.objectContaining({
      eventType: 'PASSWORD_RESET_REQUEST',
      userIdentifier: 'user@example.com',
    }));
  });

  test('logs PASSWORD_RESET_COMPLETE for complete phase', async () => {
    const db = createMockDb();
    const app = buildApp(db);

    const res = await request(app)
      .post('/api/auth/audit/password-reset')
      .send({ email: 'user@example.com', phase: 'complete' });

    expect(res.status).toBe(200);
    expect(mockLogAuditEvent).toHaveBeenCalledWith(db, expect.objectContaining({
      eventType: 'PASSWORD_RESET_COMPLETE',
    }));
  });

  test('returns 400 for invalid phase', async () => {
    const db = createMockDb();
    const app = buildApp(db);

    const res = await request(app)
      .post('/api/auth/audit/password-reset')
      .send({ email: 'user@example.com', phase: 'invalid' });

    expect(res.status).toBe(400);
  });

  test('returns 400 when phase is missing', async () => {
    const db = createMockDb();
    const app = buildApp(db);

    const res = await request(app)
      .post('/api/auth/audit/password-reset')
      .send({ email: 'user@example.com' });

    expect(res.status).toBe(400);
  });
});
