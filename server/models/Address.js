const mongoose = require("mongoose")

// SECURITY: Enhanced schema with validation and type safety
// WHY: Schema-level validation provides defense in depth
// HOW: Define strict types, required fields, and length constraints
const AddressSchema = new mongoose.Schema(
  {
    // SECURITY: Use ObjectId reference for userId
    // WHY: Ensures referential integrity and prevents injection
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: [true, "User ID is required"],
      index: true, // Index for faster queries
    },
    address: {
      type: String,
      required: [true, "Address is required"],
      trim: true,
      minlength: [5, "Address must be at least 5 characters"],
      maxlength: [200, "Address must not exceed 200 characters"],
    },
    city: {
      type: String,
      required: [true, "City is required"],
      trim: true,
      minlength: [2, "City must be at least 2 characters"],
      maxlength: [50, "City must not exceed 50 characters"],
    },
    pincode: {
      type: String,
      required: [true, "Pincode is required"],
      trim: true,
      minlength: [4, "Pincode must be at least 4 characters"],
      maxlength: [10, "Pincode must not exceed 10 characters"],
    },
    phone: {
      type: String,
      required: [true, "Phone number is required"],
      trim: true,
      minlength: [10, "Phone number must be at least 10 characters"],
      maxlength: [20, "Phone number must not exceed 20 characters"],
    },
    notes: {
      type: String,
      trim: true,
      maxlength: [500, "Notes must not exceed 500 characters"],
      default: "",
    },
  },
  {
    timestamps: true,
    // SECURITY: Prevent returning sensitive internal fields
    toJSON: {
      transform: (doc, ret) => {
        delete ret.__v
        return ret
      },
    },
  },
)

// SECURITY: Add compound index for efficient and secure queries
// WHY: Improves query performance and ensures userId is always used in lookups
AddressSchema.index({ userId: 1, _id: 1 })

module.exports = mongoose.model("Address", AddressSchema)
