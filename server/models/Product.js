const mongoose = require("mongoose");

// WHY: Original schema had no validation, allowing any malicious data to be stored
// HOW: Add strict validation, length limits, enums, and indexes for security and performance
const ProductSchema = new mongoose.Schema(
  {
    image: {
      type: String,
      required: [true, "Product image is required"],
      trim: true,
      maxlength: [500, "Image URL too long"],
    },
    title: {
      type: String,
      required: [true, "Product title is required"],
      trim: true,
      minlength: [3, "Title must be at least 3 characters"],
      maxlength: [200, "Title must not exceed 200 characters"],
      index: true, // For efficient searching
    },
    description: {
      type: String,
      required: [true, "Product description is required"],
      trim: true,
      minlength: [10, "Description must be at least 10 characters"],
      maxlength: [2000, "Description must not exceed 2000 characters"],
    },
    category: {
      type: String,
      required: [true, "Product category is required"],
      trim: true,
      lowercase: true,
      // WHY: Prevent injection of arbitrary category values
      // HOW: Use enum to whitelist allowed categories
      enum: {
        values: ["men", "women", "kids", "accessories", "footwear"],
        message: "Invalid category value",
      },
      index: true, // For efficient filtering
    },
    brand: {
      type: String,
      required: [true, "Product brand is required"],
      trim: true,
      minlength: [2, "Brand must be at least 2 characters"],
      maxlength: [100, "Brand must not exceed 100 characters"],
      index: true, // For efficient filtering
    },
    price: {
      type: Number,
      required: [true, "Product price is required"],
      min: [0, "Price cannot be negative"],
      max: [10000000, "Price exceeds maximum allowed"],
    },
    salePrice: {
      type: Number,
      min: [0, "Sale price cannot be negative"],
      max: [10000000, "Sale price exceeds maximum allowed"],
      validate: {
        validator: function (value) {
          return !value || value < this.price;
        },
        message: "Sale price must be less than regular price",
      },
    },
    totalStock: {
      type: Number,
      required: [true, "Total stock is required"],
      min: [0, "Stock cannot be negative"],
      max: [1000000, "Stock exceeds maximum allowed"],
      default: 0,
    },
    averageReview: {
      type: Number,
      default: 0,
      min: [0, "Rating cannot be negative"],
      max: [5, "Rating cannot exceed 5"],
    },
  },
  { 
    timestamps: true,
    // WHY: Remove version key from responses to reduce data exposure
    toJSON: {
      transform: (doc, ret) => {
        delete ret.__v;
        return ret;
      },
    },
  }
);

// WHY: Improve query performance and prevent full table scans
// HOW: Add compound indexes for common query patterns
ProductSchema.index({ category: 1, brand: 1 });
ProductSchema.index({ price: 1 });

module.exports = mongoose.model("Product", ProductSchema);