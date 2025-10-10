const express = require("express");

const {
  addToCart,
  fetchCartItems,
  deleteCartItem,
  updateCartItemQty,
} = require("../../controllers/shop/cart-controller");

const { userOnly } = require("../../middleware/roleCheck");
const { authMiddleware } = require("../../controllers/auth/auth-controller");

const router = express.Router();

router.post("/add", authMiddleware, userOnly, addToCart);
router.get("/get/:userId", authMiddleware, userOnly, fetchCartItems);
router.put("/update-cart", authMiddleware, userOnly, updateCartItemQty);
router.delete("/:userId/:productId", authMiddleware, userOnly, deleteCartItem);

module.exports = router;