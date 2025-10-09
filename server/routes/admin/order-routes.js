const express = require("express");

// SECURITY: Import authentication and authorization middleware
// WHY: Prevent unauthorized access to admin functions
// HOW: Implement role-based access control
const { authMiddleware } = require("../../middleware/auth-middleware");
const { adminMiddleware } = require("../../middleware/admin-middleware");
const { rateLimit } = require("../../middleware/rate-limit-middleware");

const {
  getAllOrdersOfAllUsers,
  getOrderDetailsForAdmin,
  updateOrderStatus,
} = require("../../controllers/admin/order-controller");

const router = express.Router();

// SECURITY: Apply authentication, admin authorization, and rate limiting to all routes
// WHY: Prevent brute force, unauthorized access, and privilege escalation
// HOW: Middleware chain for comprehensive protection
router.get("/get", 
  authMiddleware, 
  adminMiddleware, 
  getAllOrdersOfAllUsers
);

router.get("/details/:id", 
  authMiddleware, 
  adminMiddleware, 
  getOrderDetailsForAdmin
);

router.put("/update/:id", 
  authMiddleware, 
  adminMiddleware, 
  updateOrderStatus
);

module.exports = router;