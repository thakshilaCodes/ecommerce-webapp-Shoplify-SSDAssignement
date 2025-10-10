// In-memory JWT blacklist for demonstration (use Redis or DB in production)
const jwtBlacklist = new Set();

function blacklistToken(token) {
  jwtBlacklist.add(token);
}

function isTokenBlacklisted(token) {
  return jwtBlacklist.has(token);
}

module.exports = { blacklistToken, isTokenBlacklisted };
