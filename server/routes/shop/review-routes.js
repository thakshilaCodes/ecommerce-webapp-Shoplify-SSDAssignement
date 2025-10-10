const express = require("express");

const {
  addProductReview,
  getProductReviews,
} = require("../../controllers/shop/product-review-controller");

const { userOnly } = require("../../middleware/roleCheck");
const { authMiddleware } = require("../../controllers/auth/auth-controller");

const router = express.Router();

router.post("/add", authMiddleware, userOnly, addProductReview);
router.get("/:productId", getProductReviews); // public

module.exports = router;