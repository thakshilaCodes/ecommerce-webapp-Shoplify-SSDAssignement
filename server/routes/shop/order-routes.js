const express = require("express");

const {
  createOrder,
  getAllOrdersByUser,
  getOrderDetails,
  capturePayment,
} = require("../../controllers/shop/order-controller");

const { userOnly } = require("../../middleware/roleCheck");
const { authMiddleware } = require("../../controllers/auth/auth-controller");

const router = express.Router();

router.post("/create", authMiddleware, userOnly, createOrder);
router.post("/capture", authMiddleware, userOnly, capturePayment);
router.get("/list/:userId", authMiddleware, userOnly, getAllOrdersByUser);
router.get("/details/:id", authMiddleware, userOnly, getOrderDetails);

module.exports = router;