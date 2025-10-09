const mongoose = require("mongoose");
const Order = require("../../models/Order");
const Product = require("../../models/Product");
const ProductReview = require("../../models/Review");

// Libraries
const { body, validationResult, param } = require("express-validator");
const sanitize = require("mongo-sanitize");

// SECURITY: Middleware for comprehensive input validation and sanitization
// WHY: Prevent injection attacks, data corruption, and business logic bypass
// HOW: Use express-validator for structured validation rules and mongo-sanitize for NoSQL injection prevention
const reviewValidationRules = [
  // SECURITY: Validate and sanitize productId
  // WHY: Prevent NoSQL injection through malformed product IDs
  // HOW: Check ObjectId validity and sanitize using mongo-sanitize
  body("productId")
    .notEmpty().withMessage("Product ID is required")
    .custom((value) => mongoose.Types.ObjectId.isValid(value))
    .withMessage("Invalid product ID format")
    .customSanitizer((value) => sanitize(value)), // SECURITY: Remove MongoDB operators

  // SECURITY: Validate and sanitize review message
  // WHY: Prevent XSS, injection, and ensure data quality
  // HOW: Length limits, character whitelisting, and input sanitization
  body("reviewMessage")
    .notEmpty().withMessage("Review message is required")
    .isLength({ min: 1, max: 1000 }).withMessage("Review must be 1-1000 chars")
    .matches(/^[a-zA-Z0-9\s\.,!?()\-'"@#:;]+$/)
    .withMessage("Review contains invalid characters")
    .customSanitizer((value) => sanitize(value)), // SECURITY: Sanitize for NoSQL injection

  // SECURITY: Validate rating value
  // WHY: Prevent invalid ratings that could break business logic
  // HOW: Ensure integer values within acceptable range (1-5)
  body("reviewValue")
    .notEmpty().withMessage("Rating is required")
    .isInt({ min: 1, max: 5 })
    .withMessage("Rating must be an integer between 1 and 5")
];

// Add Product Review
const addProductReview = async (req, res) => {
  try {
    // SECURITY: Run validation rules before processing
    // WHY: Catch input validation errors early in the request lifecycle
    // HOW: Use express-validator's validationResult to check for errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    const { productId, reviewMessage, reviewValue } = req.body;

    // SECURITY: Authenticated user verification
    // WHY: Prevent unauthorized review submissions and user impersonation
    // HOW: Verify user exists in request object from authentication middleware
    if (!req.user || !req.user._id) {
      return res.status(401).json({ success: false, message: "Authentication required" });
    }

    const userId = req.user._id;
    // SECURITY: Sanitize username to prevent injection
    // WHY: User-controlled data could contain malicious payloads
    // HOW: Apply mongo-sanitize to username from authenticated user
    const userName = sanitize(req.user.userName);

    // SECURITY: Business logic validation - purchase verification
    // WHY: Prevent fake reviews from users who haven't purchased the product
    // HOW: Check order history for product purchase using ObjectId for safe query
    const order = await Order.findOne({
      userId,
      "cartItems.productId": mongoose.Types.ObjectId(productId), // SECURITY: Type-safe query
    });

    if (!order) {
      return res.status(403).json({ 
        success: false, 
        message: "You must purchase the product before reviewing it." 
      });
    }

    // SECURITY: Prevent duplicate reviews
    // WHY: Ensure each user can only review a product once
    // HOW: Check for existing reviews using ObjectId for safe database query
    const existingReview = await ProductReview.findOne({
      productId: mongoose.Types.ObjectId(productId), // SECURITY: Type-safe query
      userId: mongoose.Types.ObjectId(userId), // SECURITY: Type-safe query
    });

    if (existingReview) {
      return res.status(400).json({ 
        success: false, 
        message: "You have already reviewed this product." 
      });
    }

    // SECURITY: Create review with validated and sanitized data
    // WHY: Ensure only safe, validated data enters the database
    // HOW: Use ObjectId constructors and pre-validated inputs
    const newReview = new ProductReview({
      productId: mongoose.Types.ObjectId(productId), // SECURITY: Type-safe storage
      userId: mongoose.Types.ObjectId(userId), // SECURITY: Type-safe storage
      userName,
      reviewMessage, // SECURITY: Already validated and sanitized
      reviewValue, // SECURITY: Already validated
    });

    await newReview.save();

    // SECURITY: Update product average rating with error handling
    // WHY: Maintain accurate product ratings while preventing application crashes
    // HOW: Separate try-catch block to isolate rating calculation errors
    try {
      const reviews = await ProductReview.find({ 
        productId: mongoose.Types.ObjectId(productId) // SECURITY: Type-safe query
      });
      
      if (reviews.length > 0) {
        const averageReview = reviews.reduce((sum, r) => sum + r.reviewValue, 0) / reviews.length;
        // SECURITY: Update with rounded value and schema validation
        // WHY: Prevent floating point precision issues and ensure data integrity
        // HOW: Round to 1 decimal and run schema validators
        await Product.findByIdAndUpdate(
          productId, 
          { averageReview: Math.round(averageReview * 10) / 10 }, 
          { runValidators: true } // SECURITY: Enforce schema validation
        );
      }
    } catch (err) {
      // SECURITY: Graceful error handling for non-critical operation
      // WHY: Prevent review creation from failing due to rating update issues
      // HOW: Log error but don't fail the main operation
      console.error("Error updating average rating:", err);
    }

    res.status(201).json({ 
      success: true, 
      data: newReview, 
      message: "Review added successfully" 
    });

  } catch (e) {
    // SECURITY: Generic error handling to prevent information disclosure
    // WHY: Detailed error messages can reveal system internals to attackers
    // HOW: Log detailed errors internally but return generic messages to clients
    console.error("Error adding review:", e);
    res.status(500).json({ 
      success: false, 
      message: "An error occurred while adding the review" 
    });
  }
};

// SECURITY: Get Product Reviews with comprehensive parameter validation
// WHY: Prevent NoSQL injection through URL parameters and ensure data safety
// HOW: Use express-validator middleware chain for parameter validation
const getProductReviews = [
  // SECURITY: Validate and sanitize productId parameter
  // WHY: Prevent NoSQL injection attacks through URL parameters
  // HOW: Validate ObjectId format and sanitize using mongo-sanitize
  param("productId")
    .custom((value) => mongoose.Types.ObjectId.isValid(value))
    .withMessage("Invalid product ID format")
    .customSanitizer((value) => sanitize(value)), // SECURITY: Sanitize URL parameter

  async (req, res) => {
    // SECURITY: Run parameter validation
    // WHY: Ensure URL parameters meet security requirements before processing
    // HOW: Check validation results before database operations
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
      const { productId } = req.params;

      // SECURITY: Safe database query with ObjectId and field projection
      // WHY: Prevent NoSQL injection and limit exposed data
      // HOW: Use ObjectId constructor and exclude internal fields
      const reviews = await ProductReview.find({ 
        productId: mongoose.Types.ObjectId(productId) // SECURITY: Type-safe query
      }).select("-__v"); // SECURITY: Exclude internal version field

      // SECURITY: Result limiting to prevent Denial of Service (DoS)
      // WHY: Prevent returning excessively large datasets that could overwhelm system
      // HOW: Implement hard limit on number of returned reviews
      const limitedReviews = reviews.slice(0, 100);

      res.status(200).json({
        success: true,
        data: limitedReviews,
        total: reviews.length,
        showing: limitedReviews.length
      });
    } catch (e) {
      // SECURITY: Generic error handling for fetch operation
      // WHY: Prevent exposure of database errors and system information
      // HOW: Return generic error message while logging details internally
      console.error("Error fetching reviews:", e);
      res.status(500).json({ 
        success: false, 
        message: "An error occurred while fetching reviews" 
      });
    }
  }
];

module.exports = { addProductReview, getProductReviews, reviewValidationRules };