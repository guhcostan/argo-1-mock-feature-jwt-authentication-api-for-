```javascript
const request = require('supertest');
const jwt = require('jsonwebtoken');
const app = require('../app');

const SECRET = process.env.JWT_SECRET || 'test-secret';

const generateToken = (payload, options = {}) => {
  return jwt.sign(payload, SECRET, { expiresIn: '1h', ...options });
};

const generateExpiredToken = (payload) => {
  return jwt.sign(payload, SECRET, { expiresIn: '-1s' });
};

describe('JWT Authentication API - Edge Case Tests', () => {

  // ─── TOKEN EDGE CASES ──────────────────────────────────────────────────────

  describe('Expired Token Handling', () => {
    test('POST /api/resource should return 401 when JWT token is expired', async () => {
      const expiredToken = generateExpiredToken({ userId: 'user-123', role: 'user' });

      const response = await request(app)
        .post('/api/resource')
        .set('Authorization', `Bearer ${expiredToken}`)
        .send({ name: 'test resource', data: 'some data' });

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toMatch(/expired|invalid/i);
    });

    test('GET /api/resource/:id should return 401 when JWT token is expired', async () => {
      const expiredToken = generateExpiredToken({ userId: 'user-123' });

      const response = await request(app)
        .get('/api/resource/some-valid-id')
        .set('Authorization', `Bearer ${expiredToken}`);

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty('error');
    });

    test('DELETE /api/resource/:id should return 401 when JWT token is expired', async () => {
      const expiredToken = generateExpiredToken({ userId: 'user-123' });

      const response = await request(app)
        .delete('/api/resource/some-valid-id')
        .set('Authorization', `Bearer ${expiredToken}`);

      expect(response.status).toBe(401);
    });
  });

  describe('Invalid Token Formats', () => {
    test('POST /api/resource should return 401 when Authorization header is missing entirely', async () => {
      const response = await request(app)
        .post('/api/resource')
        .send({ name: 'test resource' });

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty('error');
    });

    test('GET /api/resource/:id should return 401 when token is a random string, not a JWT', async () => {
      const response = await request(app)
        .get('/api/resource/123')
        .set('Authorization', 'Bearer this-is-not-a-jwt-token');

      expect(response.status).toBe(401);
    });

    test('POST /api/resource should return 401 when token is signed with wrong secret', async () => {
      const wrongSecretToken = jwt.sign({ userId: 'user-123' }, 'wrong-secret', { expiresIn: '1h' });

      const response = await request(app)
        .post('/api/resource')
        .set('Authorization', `Bearer ${wrongSecretToken}`)
        .send({ name: 'test resource' });

      expect(response.status).toBe(401);
    });

    test('POST /api/resource should return 401 when Authorization header uses wrong scheme (Basic instead of Bearer)', async () => {
      const validToken = generateToken({ userId: 'user-123' });

      const response = await request(app)
        .post('/api/resource')
        .set('Authorization', `Basic ${validToken}`)
        .send({ name: 'test resource' });

      expect(response.status).toBe(401);
    });

    test('POST /api/resource should return 401 when token is an empty string', async () => {
      const response = await request(app)
        .post('/api/resource')
        .set('Authorization', 'Bearer ')
        .send({ name: 'test resource' });

      expect(response.status).toBe(401);
    });

    test('POST /api/resource should return 401 when token has tampered payload (modified base64 segment)', async () => {
      const validToken = generateToken({ userId: 'user-123', role: 'user' });
      const parts = validToken.split('.');
      // Tamper payload by base64-encoding a different payload
      const tamperedPayload = Buffer.from(JSON.stringify({ userId: 'admin', role: 'admin' })).toString('base64url');
      const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

      const response = await request(app)
        .post('/api/resource')
        .set('Authorization', `Bearer ${tamperedToken}`)
        .send({ name: 'test resource' });

      expect(response.status).toBe(401);
    });

    test('POST /api/resource should return 401 when JWT has only two segments instead of three', async () => {
      const response = await request(app)
        .post('/api/resource')
        .set('Authorization', 'Bearer header.payload')
        .send({ name: 'test resource' });

      expect(response.status).toBe(401);
    });

    test('POST /api/resource should return 401 when token algorithm is set to "none" (algorithm confusion attack)', async () => {
      const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ userId: 'user-123', exp: Math.floor(Date.now() / 1000) + 3600 })).toString('base64url');
      const noneAlgToken = `${header}.${payload}.`;

      const response = await request(app)
        .post('/api/resource')
        .set('Authorization', `Bearer ${noneAlgToken}`)
        .send({ name: 'test resource' });

      expect(response.status).toBe(401);
    });
  });

  // ─── INPUT VALIDATION EDGE CASES ───────────────────────────────────────────

  describe('Empty and Missing Input', () => {
    test('POST /api/resource should return 400 when request body is completely empty', async () => {
      const validToken = generateToken({ userId: 'user-123' });

      const response = await request(app)
        .post('/api/resource')
        .set('Authorization', `Bearer ${validToken}`)
        .send({});

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('error');
    });

    test('POST /api/resource should return 400 when required fields are missing from body', async () => {
      const validToken = generateToken({ userId: 'user-123' });

      const response = await request(app)
        .post('/api/resource')
        .set('Authorization', `Bearer ${validToken}`)
        .send({ unexpectedField: 'some value' });

      expect(response.status).toBe(400);
    });

    test('POST /api/resource should return 400 when body fields contain only whitespace', async () => {
      const validToken = generateToken({ userId: 'user-123' });

      const response = await request(app)
        .post('/api/resource')
        .set('Authorization', `Bearer ${validToken}`)
        .send({ name: '   ', data: '\t\n' });

      expect(response.status).toBe(400);
    });

    test('POST /api/resource should return 400 or handle gracefully when body is null', async () => {
      const validToken = generateToken({ userId: 'user-123' });

      const response = await request(app)
        .post('/api/resource')
        .set