const crypto = require('crypto');

describe('OAuth State Parameter', () => {
  it('should generate a cryptographically random state', () => {
    const state1 = crypto.randomBytes(16).toString('hex');
    const state2 = crypto.randomBytes(16).toString('hex');
    expect(state1).not.toBe(state2);
    expect(state1).toHaveLength(32);
  });
});
