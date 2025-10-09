const mongoose = require("mongoose");

// Sanitize strings to prevent NoSQL injection and XSS
const sanitizeString = (str) => {
  if (typeof str !== "string") return str;
  return str.replace(/[${}]/g, "").trim();
};

const ProductReviewSchema = new mongoose.Schema(
  {
    productId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Product",
      required: [true, "Product ID is required"],
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: [true, "User ID is required"],
    },
    userName: {
      type: String,
      required: [true, "User name is required"],
      maxlength: [100, "User name too long"],
      set: sanitizeString,
    },
    reviewMessage: {
      type: String,
      required: [true, "Review message is required"],
      maxlength: [500, "Review message too long"],
      set: sanitizeString,
    },
    reviewValue: {
      type: Number,
      required: [true, "Review value is required"],
      min: 1,
      max: 5,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("ProductReview", ProductReviewSchema);
