const express = require("express");
const { addProductReview, getProductReviews } = require("../../controllers/shop/product-review-controller");
const { authMiddleware } = require("../../controllers/auth/auth-controller");

const router = express.Router();

// POST route is protected
router.post("/add", authMiddleware, addProductReview);

// GET route is public
router.get("/:productId", getProductReviews);

module.exports = router;
