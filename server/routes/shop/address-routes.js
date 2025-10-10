const express = require("express");

const {
  addAddress,
  fetchAllAddress,
  editAddress,
  deleteAddress,
} = require("../../controllers/shop/address-controller");

const { authMiddleware } = require("../../controllers/auth/auth-controller");

// WHY: Protect routes so only normal users (not admins) can access their addresses
// HOW: Apply `userOnly` middleware after authentication to enforce role-based access
const { userOnly } = require("../../middleware/roleCheck");

const router = express.Router();

// =========================
// Address Routes
// =========================

// SECURITY: All routes require authentication and user role
router.post("/add", authMiddleware, userOnly, addAddress);
router.get("/get/:userId", authMiddleware, userOnly, fetchAllAddress);
router.delete("/delete/:userId/:addressId", authMiddleware, userOnly, deleteAddress);
router.put("/update/:userId/:addressId", authMiddleware, userOnly, editAddress);

module.exports = router;
