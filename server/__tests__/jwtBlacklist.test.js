const { blacklistToken, isTokenBlacklisted } = require('../middleware/jwtBlacklist');

describe('JWT Blacklist', () => {
  const token = 'sometoken';

  it('should not be blacklisted initially', () => {
    expect(isTokenBlacklisted(token)).toBe(false);
  });

  it('should be blacklisted after calling blacklistToken', () => {
    blacklistToken(token);
    expect(isTokenBlacklisted(token)).toBe(true);
  });
});
