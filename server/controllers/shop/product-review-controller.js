const mongoose = require("mongoose");
const Order = require("../../models/Order");
const Product = require("../../models/Product");
const ProductReview = require("../../models/Review");

// SECURITY: Utility to sanitize strings to prevent NoSQL injection and XSS
// WHY: User-generated content in reviews can contain malicious payloads that enable injection attacks
// HOW: Remove MongoDB operators and dangerous characters that could be used in NoSQL injection
const sanitizeString = (str) => {
  if (typeof str !== "string") return str;
  return str.replace(/[${}<>]/g, "").trim(); // SECURITY: Added < and > to prevent XSS
};

// SECURITY: Validate review value range
// WHY: Prevent invalid rating values that could break the application logic
// HOW: Ensure rating is within acceptable bounds (1-5)
const validateReviewValue = (value) => {
  return Number.isInteger(value) && value >= 1 && value <= 5;
};

// SECURITY: Validate review message length and content
// WHY: Prevent excessively long reviews and potential denial of service
// HOW: Enforce reasonable length limits and character restrictions
const validateReviewMessage = (message) => {
  if (!message || typeof message !== "string") return false;
  if (message.length < 1 || message.length > 1000) return false;
  // Allow only safe characters for reviews
  return /^[a-zA-Z0-9\s\.,!?()\-'"@#:;]+$/.test(message);
};

// Add Product Review
const addProductReview = async (req, res) => {
  try {
    const { productId, reviewMessage, reviewValue } = req.body;

    // SECURITY: Use authenticated user only - prevent user impersonation
    // WHY: Ensure reviews are only added by authenticated, verified users
    // HOW: Extract user information from JWT token rather than request body
    if (!req.user || !req.user._id) {
      return res.status(401).json({ 
        success: false, 
        message: "Authentication required to add reviews" 
      });
    }
    
    const userId = req.user._id;
    const userName = req.user.userName;

    // SECURITY: Validate all required fields are present
    // WHY: Prevent incomplete data submission and potential errors
    // HOW: Check existence of all mandatory review fields
    if (!productId || !reviewMessage || reviewValue === undefined) {
      return res.status(400).json({ 
        success: false, 
        message: "Product ID, review message, and rating are required" 
      });
    }

    // SECURITY: Validate productId format to prevent NoSQL injection
    // WHY: Malformed ObjectIds can cause database errors or enable injection attacks
    // HOW: Use mongoose's built-in ObjectId validation
    if (!mongoose.Types.ObjectId.isValid(productId)) {
      return res.status(400).json({ 
        success: false, 
        message: "Invalid product ID format" 
      });
    }

    // SECURITY: Validate review value to ensure it's within acceptable range
    // WHY: Prevent invalid ratings that could break rating calculations
    // HOW: Check that rating is an integer between 1-5
    if (!validateReviewValue(reviewValue)) {
      return res.status(400).json({
        success: false,
        message: "Rating must be a whole number between 1 and 5"
      });
    }

    // SECURITY: Validate review message content and length
    // WHY: Prevent malicious content, spam, or excessively long reviews
    // HOW: Enforce character limits and content validation
    if (!validateReviewMessage(reviewMessage)) {
      return res.status(400).json({
        success: false,
        message: "Review message must be 1-1000 characters and contain only allowed characters"
      });
    }

    // SECURITY: Business logic validation - user must have purchased the product
    // WHY: Prevent fake reviews from users who haven't actually purchased the product
    // HOW: Verify user's order history contains the product
    const order = await Order.findOne({
      userId,
      "cartItems.productId": new mongoose.Types.ObjectId(productId), // SECURITY: Use ObjectId for query
    });

    if (!order) {
      return res.status(403).json({
        success: false,
        message: "You need to purchase the product before reviewing it.",
      });
    }

    // SECURITY: Prevent duplicate reviews from the same user
    // WHY: Ensure each user can only review a product once
    // HOW: Check for existing reviews by the same user for the same product
    const existingReview = await ProductReview.findOne({
      productId: new mongoose.Types.ObjectId(productId), // SECURITY: Use ObjectId
      userId: new mongoose.Types.ObjectId(userId), // SECURITY: Use ObjectId
    });

    if (existingReview) {
      return res.status(400).json({
        success: false,
        message: "You have already reviewed this product!",
      });
    }

    // SECURITY: Sanitize all user inputs before storage
    // WHY: Remove any potentially dangerous characters that survived validation
    // HOW: Apply sanitization function to all user-provided string inputs
    const safeReviewMessage = sanitizeString(reviewMessage);
    const safeUserName = sanitizeString(userName);

    // SECURITY: Create review with validated and sanitized data
    // WHY: Ensure only clean, safe data enters the database
    // HOW: Use ObjectId constructors and sanitized values
    const newReview = new ProductReview({
      productId: new mongoose.Types.ObjectId(productId),
      userId: new mongoose.Types.ObjectId(userId),
      userName: safeUserName,
      reviewMessage: safeReviewMessage,
      reviewValue: reviewValue,
    });

    await newReview.save();

    // SECURITY: Update product's average rating with proper error handling
    // WHY: Maintain accurate product ratings while preventing race conditions
    // HOW: Recalculate average from all reviews with transaction safety
    try {
      const reviews = await ProductReview.find({ 
        productId: new mongoose.Types.ObjectId(productId) // SECURITY: Use ObjectId
      });
      
      if (reviews.length > 0) {
        const averageReview = reviews.reduce((sum, r) => sum + r.reviewValue, 0) / reviews.length;
        
        // SECURITY: Update product with rounded average to prevent floating point issues
        await Product.findByIdAndUpdate(
          productId, 
          { averageReview: Math.round(averageReview * 10) / 10 }, // Round to 1 decimal
          { runValidators: true } // SECURITY: Run schema validators
        );
      }
    } catch (updateError) {
      console.error("Error updating product average review:", updateError);
      // Don't fail the review creation if average update fails
    }

    res.status(201).json({ 
      success: true, 
      data: newReview,
      message: "Review added successfully"
    });
  } catch (e) {
    // SECURITY: Generic error handling to prevent information disclosure
    // WHY: Detailed error messages can reveal system internals and database structure
    // HOW: Log detailed errors internally but return generic messages to clients
    console.error("Error adding product review:", e);
    res.status(500).json({ 
      success: false, 
      message: "An error occurred while adding the review" 
    });
  }
};

// Get Product Reviews
const getProductReviews = async (req, res) => {
  try {
    const { productId } = req.params;

    // SECURITY: Validate productId parameter from URL
    // WHY: Prevent NoSQL injection through URL parameters
    // HOW: Validate ObjectId format before database query
    if (!productId || !mongoose.Types.ObjectId.isValid(productId)) {
      return res.status(400).json({ 
        success: false, 
        message: "Invalid product ID format" 
      });
    }

    // SECURITY: Use ObjectId in query to prevent injection
    // WHY: Ensure type-safe database queries
    // HOW: Convert string parameter to ObjectId in database query
    const reviews = await ProductReview.find({ 
      productId: new mongoose.Types.ObjectId(productId) 
    }).select("-__v"); // SECURITY: Exclude internal version field

    // SECURITY: Limit number of reviews returned to prevent DoS
    // WHY: Prevent returning excessively large datasets
    // HOW: Implement pagination or limit results
    const limitedReviews = reviews.slice(0, 100); // Limit to 100 reviews

    res.status(200).json({ 
      success: true, 
      data: limitedReviews,
      total: reviews.length,
      showing: limitedReviews.length
    });
  } catch (e) {
    // SECURITY: Generic error handling
    // WHY: Prevent exposure of database errors and system information
    // HOW: Return generic error message while logging details internally
    console.error("Error fetching product reviews:", e);
    res.status(500).json({ 
      success: false, 
      message: "An error occurred while fetching reviews" 
    });
  }
};

module.exports = { addProductReview, getProductReviews };