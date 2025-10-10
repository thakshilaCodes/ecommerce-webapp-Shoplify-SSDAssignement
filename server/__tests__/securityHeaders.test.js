const helmet = require('helmet');
const helmetCsp = require('helmet-csp');
const express = require('express');
const request = require('supertest');

describe('Security Headers', () => {
  const app = express();
  app.use(helmet());
  app.use(helmetCsp({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
    },
  }));
  app.get('/', (req, res) => res.send('ok'));

  it('should set security headers', async () => {
    const res = await request(app).get('/');
    expect(res.headers['x-dns-prefetch-control']).toBeDefined();
    expect(res.headers['content-security-policy']).toBeDefined();
  });
});
