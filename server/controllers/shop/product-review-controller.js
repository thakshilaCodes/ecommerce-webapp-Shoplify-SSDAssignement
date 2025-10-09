const mongoose = require("mongoose");
const Order = require("../../models/Order");
const Product = require("../../models/Product");
const ProductReview = require("../../models/Review");

// Utility to sanitize strings for NoSQL injection / XSS
const sanitizeString = (str) => {
  if (typeof str !== "string") return str;
  return str.replace(/[${}]/g, "").trim();
};

// Add Product Review
const addProductReview = async (req, res) => {
  try {
    const { productId, reviewMessage, reviewValue } = req.body;

    // SECURITY: Use authenticated user ID instead of trusting client input
    const userId = req.user._id;
    const userName = req.user.userName;

    // VALIDATE: productId must be a valid ObjectId
    if (!mongoose.Types.ObjectId.isValid(productId)) {
      return res.status(400).json({ success: false, message: "Invalid product ID" });
    }

    // CHECK: user purchased the product
    const order = await Order.findOne({
      userId,
      "cartItems.productId": productId,
    });

    if (!order) {
      return res.status(403).json({
        success: false,
        message: "You need to purchase product to review it.",
      });
    }

    // CHECK: Already reviewed
    const existingReview = await ProductReview.findOne({
      productId,
      userId,
    });

    if (existingReview) {
      return res.status(400).json({
        success: false,
        message: "You already reviewed this product!",
      });
    }

    // SANITIZE inputs at controller-level for defense-in-depth
    const safeReviewMessage = sanitizeString(reviewMessage);
    const safeUserName = sanitizeString(userName);

    // CREATE review
    const newReview = new ProductReview({
      productId,
      userId,
      userName: safeUserName,
      reviewMessage: safeReviewMessage,
      reviewValue,
    });

    await newReview.save();

    // RECALCULATE average review
    const reviews = await ProductReview.find({ productId });
    const averageReview =
      reviews.reduce((sum, r) => sum + r.reviewValue, 0) / reviews.length;

    await Product.findByIdAndUpdate(productId, { averageReview });

    res.status(201).json({ success: true, data: newReview });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, message: "Error" });
  }
};

// Get Product Reviews
const getProductReviews = async (req, res) => {
  try {
    const { productId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(productId)) {
      return res.status(400).json({ success: false, message: "Invalid product ID" });
    }

    const reviews = await ProductReview.find({ productId });
    res.status(200).json({ success: true, data: reviews });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, message: "Error" });
  }
};

module.exports = { addProductReview, getProductReviews };
