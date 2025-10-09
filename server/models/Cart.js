const mongoose = require("mongoose");

// SECURITY: Enhanced Cart Schema with comprehensive security measures
// WHY: Prevent NoSQL injection, data corruption, cart manipulation, and DoS attacks
// HOW: Add validation, sanitization, limits, and security middleware

const CartItemSchema = new mongoose.Schema({
  productId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Product",
    required: [true, "Product ID is required"],
    validate: {
      validator: function(v) {
        return mongoose.Types.ObjectId.isValid(v);
      },
      message: "Invalid product ID format"
    }
  },
  quantity: {
    type: Number,
    required: [true, "Quantity is required"],
    min: [1, "Quantity must be at least 1"],
    max: [50, "Cannot add more than 50 of a single product"], // SECURITY: Prevent bulk abuse
    validate: {
      validator: Number.isInteger,
      message: "Quantity must be a whole number"
    }
  },
  addedAt: {
    type: Date,
    default: Date.now
  },
  priceSnapshot: { // SECURITY: Store price at time of adding to prevent price manipulation
    type: Number,
    min: [0, "Price cannot be negative"],
    max: [100000, "Price cannot exceed 100,000"] // SECURITY: Prevent financial abuse
  }
}, {
  _id: true
});



module.exports = mongoose.model("Cart", CartSchema);