const express = require("express");

const {
  getAllOrdersOfAllUsers,
  getOrderDetailsForAdmin,
  updateOrderStatus,
} = require("../../controllers/admin/order-controller");

const { adminOnly } = require("../../middleware/roleCheck");
const { authMiddleware } = require("../../controllers/auth/auth-controller");

const router = express.Router();

// All admin order routes require authentication and admin role
router.get("/get", authMiddleware, adminOnly, getAllOrdersOfAllUsers);
router.get("/details/:id", authMiddleware, adminOnly, getOrderDetailsForAdmin);
router.put("/update/:id", authMiddleware, adminOnly, updateOrderStatus);

module.exports = router;