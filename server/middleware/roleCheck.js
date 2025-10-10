// Middleware to check if user is authenticated (requires authMiddleware before this)
const adminOnly = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({
      success: false,
      message: 'Forbidden: Admins only.'
    });
  }
  next();
};

const userOnly = (req, res, next) => {
  if (!req.user || req.user.role !== 'user') {
    return res.status(403).json({
      success: false,
      message: 'Forbidden: Users only.'
    });
  }
  next();
};

module.exports = { adminOnly, userOnly };
