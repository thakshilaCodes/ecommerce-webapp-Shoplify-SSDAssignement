// In-memory failed login tracker (use Redis or DB in production)
const failedLogins = {};
const LOCK_TIME = 15 * 60 * 1000; // 15 minutes
const MAX_ATTEMPTS = 5;

function recordFailedLogin(email) {
  if (!failedLogins[email]) {
    failedLogins[email] = { count: 1, lockUntil: null };
  } else {
    failedLogins[email].count += 1;
    if (failedLogins[email].count >= MAX_ATTEMPTS) {
      failedLogins[email].lockUntil = Date.now() + LOCK_TIME;
    }
  }
}

function isLocked(email) {
  const entry = failedLogins[email];
  if (!entry) return false;
  if (entry.lockUntil && entry.lockUntil > Date.now()) return true;
  if (entry.lockUntil && entry.lockUntil <= Date.now()) {
    // Unlock after lock time
    delete failedLogins[email];
    return false;
  }
  return false;
}

function resetFailedLogins(email) {
  delete failedLogins[email];
}

module.exports = { recordFailedLogin, isLocked, resetFailedLogins };
