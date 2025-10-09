const express = require("express");

// SECURITY: Import security middleware
// WHY: Prevent unauthorized access and abuse
// HOW: Implement authentication and rate limiting
const { authMiddleware } = require("../../middleware/auth-middleware");
const { rateLimit } = require("../../middleware/rate-limit-middleware");
const { validateObjectId } = require("../../middleware/validation-middleware");

const {
  createOrder,
  getAllOrdersByUser,
  getOrderDetails,
  capturePayment,
} = require("../../controllers/shop/order-controller");

const router = express.Router();

// SECURITY: Apply authentication to all order routes
// WHY: Prevent unauthorized order operations
// HOW: Authentication middleware on all routes
router.use(authMiddleware);

// SECURITY: Stricter rate limiting for order creation and payment
// WHY: Prevent financial abuse and spam
// HOW: Different rate limits based on endpoint sensitivity
router.post("/create", 
  createOrder
);

router.post("/capture", 
  capturePayment
);

// SECURITY: Validate user ID parameter to prevent IDOR
// WHY: Prevent users from accessing other users' orders
// HOW: Parameter validation and authorization checks
router.get("/list/:userId", 
  validateObjectId('userId'), // Validate MongoDB ObjectId format
  getAllOrdersByUser
);

// SECURITY: Validate order ID parameter
// WHY: Prevent NoSQL injection through malformed IDs
// HOW: ObjectId validation middleware
router.get("/details/:id", 
  validateObjectId('id'),
  getOrderDetails
);

module.exports = router;