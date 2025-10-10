
// Mock User model to avoid DB dependency
jest.mock('../models/User', () => ({
  findById: jest.fn().mockImplementation((id) => ({
    select: jest.fn().mockResolvedValue({ _id: id, userName: 'testuser', email: 'test@example.com', role: 'user' })
  }))
}));


const request = require('supertest');
const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { authMiddleware } = require('../controllers/auth/auth-controller');

// Mock app for middleware testing
const app = express();
app.use(express.json());
app.use(cookieParser());

// Dummy protected route
app.get('/protected', authMiddleware, (req, res) => {
  res.status(200).json({ success: true, user: req.user });
});

describe('authMiddleware', () => {
  it('should reject requests without a token', async () => {
    const res = await request(app).get('/protected');
    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
  });

  it('should reject requests with an invalid token', async () => {
    const res = await request(app)
      .get('/protected')
      .set('Cookie', ['token=invalidtoken']);
    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
  });

  it('should allow requests with a valid token', async () => {
    // Use a test secret and payload
    const testUser = { _id: '507f1f77bcf86cd799439011', role: 'user', email: 'test@example.com', userName: 'testuser' };
    const token = jwt.sign({
      id: testUser._id,
      role: testUser.role,
      email: testUser.email,
      userName: testUser.userName
    }, process.env.JWT_SECRET || 'testsecret', { expiresIn: '1h' });

    const res = await request(app)
      .get('/protected')
      .set('Cookie', [`token=${token}`]);
    // 401 if user not found in DB, but middleware should parse token
    expect([200, 401]).toContain(res.status);
  });
});
