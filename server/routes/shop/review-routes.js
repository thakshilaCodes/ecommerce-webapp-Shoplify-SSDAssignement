const express = require("express");
const { addProductReview, getProductReviews } = require("../../controllers/shop/product-review-controller");
const { authMiddleware } = require("../../controllers/auth/auth-controller"); // protect routes

const router = express.Router();

// SECURITY: Only authenticated users can add a review
router.post("/add", authMiddleware, addProductReview);
router.get("/:productId", getProductReviews);

module.exports = router;
