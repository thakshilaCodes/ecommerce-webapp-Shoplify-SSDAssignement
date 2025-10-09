const Address = require("../../models/Address")
const mongoose = require("mongoose")

// SECURITY: Input validation and sanitization helper
// WHY: Prevents NoSQL injection and XSS attacks by validating all user inputs
// HOW: Uses regex patterns to validate format and removes dangerous characters
const validateAndSanitizeAddressInput = (input) => {
  const errors = []

  // Validate address (alphanumeric, spaces, commas, hyphens, periods)
  if (!input.address || typeof input.address !== "string") {
    errors.push("Address is required")
  } else if (input.address.length < 5 || input.address.length > 200) {
    errors.push("Address must be between 5 and 200 characters")
  } else if (!/^[a-zA-Z0-9\s,.\-#/]+$/.test(input.address)) {
    errors.push("Address contains invalid characters")
  }

  // Validate city (letters, spaces, hyphens only)
  if (!input.city || typeof input.city !== "string") {
    errors.push("City is required")
  } else if (input.city.length < 2 || input.city.length > 50) {
    errors.push("City must be between 2 and 50 characters")
  } else if (!/^[a-zA-Z\s-]+$/.test(input.city)) {
    errors.push("City contains invalid characters")
  }

  // Validate pincode (5-10 digits, may contain spaces or hyphens)
  if (!input.pincode || typeof input.pincode !== "string") {
    errors.push("Pincode is required")
  } else if (!/^[0-9\s-]{4,10}$/.test(input.pincode)) {
    errors.push("Invalid pincode format")
  }

  // Validate phone (10-15 digits, may contain +, spaces, hyphens, parentheses)
  if (!input.phone || typeof input.phone !== "string") {
    errors.push("Phone is required")
  } else if (!/^[+]?[(]?[0-9]{1,4}[)]?[\s-]?[(]?[0-9]{1,4}[)]?[\s-]?[0-9]{3,4}[\s-]?[0-9]{3,4}$/.test(input.phone)) {
    errors.push("Invalid phone number format")
  }

  // Validate notes (optional, but limit length and characters)
  if (input.notes) {
    if (typeof input.notes !== "string") {
      errors.push("Notes must be a string")
    } else if (input.notes.length > 500) {
      errors.push("Notes must not exceed 500 characters")
    } else if (!/^[a-zA-Z0-9\s,.\-!?()]+$/.test(input.notes)) {
      errors.push("Notes contain invalid characters")
    }
  }

  return {
    isValid: errors.length === 0,
    errors,
    sanitized: {
      address: input.address?.trim(),
      city: input.city?.trim(),
      pincode: input.pincode?.trim(),
      phone: input.phone?.trim(),
      notes: input.notes?.trim() || "",
    },
  }
}

const addAddress = async (req, res) => {
  try {
    // SECURITY VULNERABILITY #1: Insecure Direct Object Reference (IDOR)
    // WHY: Taking userId from req.body allows any user to create addresses for other users
    // HOW: Use authenticated user's ID from req.user (set by authMiddleware)
    // BEFORE: const { userId, address, city, pincode, phone, notes } = req.body;
    // AFTER: Get userId from authenticated session
    const userId = req.user.id
    const { address, city, pincode, phone, notes } = req.body

    // SECURITY VULNERABILITY #2: Missing Input Validation
    // WHY: Unvalidated input can lead to NoSQL injection, XSS, and data corruption
    // HOW: Validate and sanitize all inputs before processing
    const validation = validateAndSanitizeAddressInput({ address, city, pincode, phone, notes })

    if (!validation.isValid) {
      return res.status(400).json({
        success: false,
        message: "Invalid input data",
        errors: validation.errors,
      })
    }

    // SECURITY VULNERABILITY #3: NoSQL Injection
    // WHY: Direct use of user input in MongoDB queries can allow injection attacks
    // HOW: Validate userId is a valid MongoDB ObjectId before using it
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid user ID format",
      })
    }

    // Use sanitized data to create address
    const newlyCreatedAddress = new Address({
      userId: new mongoose.Types.ObjectId(userId),
      ...validation.sanitized,
    })

    await newlyCreatedAddress.save()

    res.status(201).json({
      success: true,
      data: newlyCreatedAddress,
      message: "Address added successfully",
    })
  } catch (e) {
    // SECURITY VULNERABILITY #4: Information Disclosure
    // WHY: Exposing error details can reveal system internals to attackers
    // HOW: Log detailed errors server-side, return generic message to client
    console.error("[Security] Error in addAddress:", e.message)
    res.status(500).json({
      success: false,
      message: "Failed to add address. Please try again.",
    })
  }
}

const fetchAllAddress = async (req, res) => {
  try {
    // SECURITY VULNERABILITY #5: Missing Authorization Check
    // WHY: Users could access other users' addresses by changing the userId parameter
    // HOW: Verify that the requested userId matches the authenticated user's ID
    const { userId } = req.params

    // Check if authenticated user matches requested userId
    if (req.user.id !== userId) {
      return res.status(403).json({
        success: false,
        message: "Unauthorized: You can only access your own addresses",
      })
    }

    // SECURITY: Validate MongoDB ObjectId format
    // WHY: Prevents NoSQL injection through malformed IDs
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid user ID format",
      })
    }

    // SECURITY: Use parameterized query with validated ObjectId
    // WHY: Prevents NoSQL injection by ensuring type safety
    const addressList = await Address.find({
      userId: new mongoose.Types.ObjectId(userId),
    }).select("-__v") // Don't expose internal version field

    res.status(200).json({
      success: true,
      data: addressList,
    })
  } catch (e) {
    console.error("[Security] Error in fetchAllAddress:", e.message)
    res.status(500).json({
      success: false,
      message: "Failed to fetch addresses. Please try again.",
    })
  }
}

const editAddress = async (req, res) => {
  try {
    const { userId, addressId } = req.params

    // SECURITY VULNERABILITY #6: Missing Authorization Check
    // WHY: Users could edit other users' addresses by changing parameters
    // HOW: Verify authenticated user matches the userId parameter
    if (req.user.id !== userId) {
      return res.status(403).json({
        success: false,
        message: "Unauthorized: You can only edit your own addresses",
      })
    }

    // SECURITY: Validate MongoDB ObjectId formats
    // WHY: Prevents NoSQL injection through malformed IDs
    if (!mongoose.Types.ObjectId.isValid(userId) || !mongoose.Types.ObjectId.isValid(addressId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid ID format",
      })
    }

    // SECURITY VULNERABILITY #7: Mass Assignment Vulnerability
    // WHY: Accepting entire formData allows users to modify fields they shouldn't (userId, _id, etc.)
    // HOW: Explicitly whitelist only the fields that can be updated
    const { address, city, pincode, phone, notes } = req.body

    // Validate and sanitize the update data
    const validation = validateAndSanitizeAddressInput({ address, city, pincode, phone, notes })

    if (!validation.isValid) {
      return res.status(400).json({
        success: false,
        message: "Invalid input data",
        errors: validation.errors,
      })
    }

    // SECURITY: Only update whitelisted fields, prevent userId modification
    // WHY: Prevents attackers from changing ownership of addresses
    const updatedAddress = await Address.findOneAndUpdate(
      {
        _id: new mongoose.Types.ObjectId(addressId),
        userId: new mongoose.Types.ObjectId(userId), // Ensure address belongs to user
      },
      {
        $set: validation.sanitized, // Only update sanitized, whitelisted fields
      },
      {
        new: true,
        runValidators: true, // Run schema validators
        select: "-__v", // Don't return version field
      },
    )

    if (!updatedAddress) {
      return res.status(404).json({
        success: false,
        message: "Address not found or you don't have permission to edit it",
      })
    }

    res.status(200).json({
      success: true,
      data: updatedAddress,
      message: "Address updated successfully",
    })
  } catch (e) {
    console.error("[Security] Error in editAddress:", e.message)
    res.status(500).json({
      success: false,
      message: "Failed to update address. Please try again.",
    })
  }
}

const deleteAddress = async (req, res) => {
  try {
    const { userId, addressId } = req.params

    // SECURITY VULNERABILITY #8: Missing Authorization Check
    // WHY: Users could delete other users' addresses by changing parameters
    // HOW: Verify authenticated user matches the userId parameter
    if (req.user.id !== userId) {
      return res.status(403).json({
        success: false,
        message: "Unauthorized: You can only delete your own addresses",
      })
    }

    // SECURITY: Validate MongoDB ObjectId formats
    // WHY: Prevents NoSQL injection through malformed IDs
    if (!mongoose.Types.ObjectId.isValid(userId) || !mongoose.Types.ObjectId.isValid(addressId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid ID format",
      })
    }

    // SECURITY: Ensure address belongs to the authenticated user
    // WHY: Double-check ownership before deletion
    const address = await Address.findOneAndDelete({
      _id: new mongoose.Types.ObjectId(addressId),
      userId: new mongoose.Types.ObjectId(userId),
    })

    if (!address) {
      return res.status(404).json({
        success: false,
        message: "Address not found or you don't have permission to delete it",
      })
    }

    res.status(200).json({
      success: true,
      message: "Address deleted successfully",
    })
  } catch (e) {
    console.error("[Security] Error in deleteAddress:", e.message)
    res.status(500).json({
      success: false,
      message: "Failed to delete address. Please try again.",
    })
  }
}

module.exports = { addAddress, editAddress, fetchAllAddress, deleteAddress }
