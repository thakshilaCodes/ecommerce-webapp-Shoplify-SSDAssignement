const { recordFailedLogin, isLocked, resetFailedLogins } = require('../middleware/loginLockout');

describe('Account Lockout Mechanism', () => {
  const email = 'lockout@example.com';

  afterEach(() => {
    resetFailedLogins(email);
  });

  it('should not lock account initially', () => {
    expect(isLocked(email)).toBe(false);
  });

  it('should lock account after 5 failed logins', () => {
    for (let i = 0; i < 5; i++) {
      recordFailedLogin(email);
    }
    expect(isLocked(email)).toBe(true);
  });

  it('should unlock after reset', () => {
    for (let i = 0; i < 5; i++) {
      recordFailedLogin(email);
    }
    resetFailedLogins(email);
    expect(isLocked(email)).toBe(false);
  });
});
