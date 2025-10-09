const mongoose = require("mongoose");

// SECURITY: Enhanced Order Schema with validation and security measures
// WHY: Prevent NoSQL injection, data corruption, and ensure data integrity
// HOW: Add validation, sanitization, and type safety
const OrderSchema = new mongoose.Schema({
  userId: {
    type: String,
    required: [true, "User ID is required"],
    validate: {
      validator: function(v) {
        return mongoose.Types.ObjectId.isValid(v);
      },
      message: "Invalid user ID format"
    }
  },
  cartId: {
    type: String,
    required: [true, "Cart ID is required"],
    validate: {
      validator: function(v) {
        return mongoose.Types.ObjectId.isValid(v);
      },
      message: "Invalid cart ID format"
    }
  },
  cartItems: [
    {
      productId: {
        type: String,
        required: [true, "Product ID is required"],
        validate: {
          validator: function(v) {
            return mongoose.Types.ObjectId.isValid(v);
          },
          message: "Invalid product ID format"
        }
      },
      title: {
        type: String,
        required: [true, "Product title is required"],
        trim: true,
        maxlength: [200, "Product title cannot exceed 200 characters"],
        match: [/^[a-zA-Z0-9\s\-_.,!?()]+$/, "Product title contains invalid characters"]
      },
      image: {
        type: String,
        required: [true, "Product image is required"],
        validate: {
          validator: function(v) {
            // Basic URL validation for image paths
            return /^(https?:\/\/.*\.(?:png|jpg|jpeg|gif|webp)|data:image\/[a-z]+;base64,|[\/\w\-.]+\.(?:png|jpg|jpeg|gif|webp))$/i.test(v);
          },
          message: "Invalid image URL format"
        }
      },
      price: {
        type: Number, // SECURITY: Changed from String to Number for type safety
        required: [true, "Price is required"],
        min: [0, "Price cannot be negative"],
        max: [1000000, "Price cannot exceed 1,000,000"] // Prevent extremely high values
      },
      quantity: {
        type: Number,
        required: [true, "Quantity is required"],
        min: [1, "Quantity must be at least 1"],
        max: [100, "Quantity cannot exceed 100"] // Prevent bulk order abuse
      }
    }
  ],
  addressInfo: {
    addressId: {
      type: String,
      required: [true, "Address ID is required"],
      validate: {
        validator: function(v) {
          return mongoose.Types.ObjectId.isValid(v);
        },
        message: "Invalid address ID format"
      }
    },
    address: {
      type: String,
      required: [true, "Address is required"],
      trim: true,
      maxlength: [200, "Address cannot exceed 200 characters"],
      match: [/^[a-zA-Z0-9\s,.\-#/]+$/, "Address contains invalid characters"]
    },
    city: {
      type: String,
      required: [true, "City is required"],
      trim: true,
      maxlength: [50, "City cannot exceed 50 characters"],
      match: [/^[a-zA-Z\s-]+$/, "City contains invalid characters"]
    },
    pincode: {
      type: String,
      required: [true, "Pincode is required"],
      trim: true,
      match: [/^[0-9\s-]{4,10}$/, "Invalid pincode format"]
    },
    phone: {
      type: String,
      required: [true, "Phone is required"],
      trim: true,
      match: [/^[+]?[(]?[0-9]{1,4}[)]?[\s-]?[(]?[0-9]{1,4}[)]?[\s-]?[0-9]{3,4}[\s-]?[0-9]{3,4}$/, "Invalid phone number format"]
    },
    notes: {
      type: String,
      trim: true,
      maxlength: [500, "Notes cannot exceed 500 characters"],
      default: "",
      match: [/^[a-zA-Z0-9\s,.\-!?()]*$/, "Notes contain invalid characters"] // Optional field
    }
  },
  orderStatus: {
    type: String,
    required: [true, "Order status is required"],
    enum: {
      values: ["pending", "confirmed", "processing", "shipped", "delivered", "cancelled", "refunded"],
      message: "Invalid order status"
    },
    default: "pending"
  },
  paymentMethod: {
    type: String,
    required: [true, "Payment method is required"],
    enum: {
      values: ["credit_card", "debit_card", "paypal", "stripe", "cash_on_delivery"],
      message: "Invalid payment method"
    }
  },
  paymentStatus: {
    type: String,
    required: [true, "Payment status is required"],
    enum: {
      values: ["pending", "completed", "failed", "refunded", "cancelled"],
      message: "Invalid payment status"
    },
    default: "pending"
  },
  totalAmount: {
    type: Number,
    required: [true, "Total amount is required"],
    min: [0, "Total amount cannot be negative"],
    max: [1000000, "Total amount cannot exceed 1,000,000"] // Prevent financial abuse
  },
  orderDate: {
    type: Date,
    default: Date.now,
    validate: {
      validator: function(v) {
        return v <= new Date();
      },
      message: "Order date cannot be in the future"
    }
  },
  orderUpdateDate: {
    type: Date,
    default: Date.now
  },
  paymentId: {
    type: String,
    trim: true,
    match: [/^[a-zA-Z0-9\-_]+$/, "Invalid payment ID format"]
  },
  payerId: {
    type: String,
    trim: true,
    match: [/^[a-zA-Z0-9\-_]+$/, "Invalid payer ID format"]
  }
}, {
  timestamps: true, // Adds createdAt and updatedAt automatically
  toJSON: {
    transform: function(doc, ret) {
      // SECURITY: Remove internal fields when converting to JSON
      delete ret.__v;
      return ret;
    }
  }
});

// SECURITY: Static method for safe order queries
// WHY: Prevent NoSQL injection through query parameters
// HOW: Parameterized query methods
OrderSchema.statics.findByUserId = function(userId) {
  if (!mongoose.Types.ObjectId.isValid(userId)) {
    throw new Error('Invalid user ID format');
  }
  return this.find({ userId }).sort({ orderDate: -1 });
};

OrderSchema.statics.findByOrderId = function(orderId) {
  if (!mongoose.Types.ObjectId.isValid(orderId)) {
    throw new Error('Invalid order ID format');
  }
  return this.findById(orderId);
};

module.exports = mongoose.model("Order", OrderSchema);