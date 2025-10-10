const Address = require("../../models/Address");
const mongoose = require("mongoose");

// SECURITY: Input sanitization to prevent NoSQL injection and XSS
// WHY: User inputs can contain malicious characters that enable NoSQL injection attacks or XSS payloads
// HOW: Remove MongoDB operators and HTML tags that could be used in injection attacks
const sanitizeInput = (input) => {
  if (typeof input !== "string") return input;
  // Remove potential NoSQL injection operators and dangerous characters
  return input.replace(/[{}$<>]/g, "").trim();
};

// SECURITY: Validate MongoDB ObjectId format
// WHY: Malformed ObjectIds can cause errors or be used in NoSQL injection attacks
// HOW: Use mongoose's built-in validation to ensure proper ObjectId format
const isValidObjectId = (id) => {
  return mongoose.Types.ObjectId.isValid(id);
};

// SECURITY: Validate phone number format
// WHY: Prevent invalid phone numbers and potential injection through phone field
// HOW: Use regex to allow only valid phone number characters and formats
const validatePhone = (phone) => {
  const phoneRegex = /^[0-9+\-\s()]{10,20}$/;
  return phoneRegex.test(phone);
};

// SECURITY: Validate pincode format
// WHY: Prevent invalid pincodes and ensure data consistency
// HOW: Restrict to digits only with reasonable length limits
const validatePincode = (pincode) => {
  const pincodeRegex = /^[0-9]{4,10}$/;
  return pincodeRegex.test(pincode);
};

// SECURITY: Validate string length
// WHY: Prevent buffer overflow attacks and ensure database consistency
// HOW: Enforce minimum and maximum length constraints
const validateLength = (str, min, max) => {
  return str && str.length >= min && str.length <= max;
};

const addAddress = async (req, res) => {
  try {
    const { userId, address, city, pincode, phone, notes } = req.body;

    // SECURITY: Validate all required fields are present
    // WHY: Missing required fields can lead to data corruption or unexpected behavior
    // HOW: Check for existence of all mandatory fields before processing
    if (!userId || !address || !city || !pincode || !phone) {
      return res.status(400).json({
        success: false,
        message: "All required fields must be provided",
      });
    }

    // SECURITY: Validate userId is a valid ObjectId
    // WHY: Prevent NoSQL injection through malformed ObjectIds
    // HOW: Use mongoose's ObjectId validation before database operations
    if (!isValidObjectId(userId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid user ID format",
      });
    }

    // SECURITY: Authorization - Verify authenticated user matches userId
    // WHY: Prevent Insecure Direct Object Reference (IDOR) - users adding addresses for other users
    // HOW: Compare authenticated user ID from JWT token with requested userId
    if (req.user && req.user.id !== userId) {
      return res.status(403).json({
        success: false,
        message: "Unauthorized: Cannot add address for another user",
      });
    }

    // SECURITY: Sanitize all string inputs
    // WHY: Remove potentially dangerous characters that could enable injection attacks
    // HOW: Apply sanitization function to all user-provided string inputs
    const sanitizedAddress = sanitizeInput(address);
    const sanitizedCity = sanitizeInput(city);
    const sanitizedPincode = sanitizeInput(pincode);
    const sanitizedPhone = sanitizeInput(phone);
    const sanitizedNotes = notes ? sanitizeInput(notes) : "";

    // SECURITY: Validate input lengths
    // WHY: Prevent database field overflow and ensure data quality
    // HOW: Enforce reasonable minimum and maximum length constraints
    if (!validateLength(sanitizedAddress, 5, 200)) {
      return res.status(400).json({
        success: false,
        message: "Address must be between 5 and 200 characters",
      });
    }

    if (!validateLength(sanitizedCity, 2, 50)) {
      return res.status(400).json({
        success: false,
        message: "City must be between 2 and 50 characters",
      });
    }

    // SECURITY: Validate phone format
    // WHY: Ensure phone number follows expected format and prevent invalid data
    // HOW: Use regex pattern matching to validate phone number structure
    if (!validatePhone(sanitizedPhone)) {
      return res.status(400).json({
        success: false,
        message: "Invalid phone number format",
      });
    }

    // SECURITY: Validate pincode format
    // WHY: Ensure pincode contains only digits and proper length
    // HOW: Use regex to restrict input to numeric characters only
    if (!validatePincode(sanitizedPincode)) {
      return res.status(400).json({
        success: false,
        message: "Pincode must be 4-10 digits",
      });
    }

    // SECURITY: Validate notes length if provided
    // WHY: Prevent excessively long notes that could impact performance
    // HOW: Enforce maximum character limit for optional fields
    if (sanitizedNotes && sanitizedNotes.length > 500) {
      return res.status(400).json({
        success: false,
        message: "Notes must not exceed 500 characters",
      });
    }

    // SECURITY: Create address with validated and sanitized data
    // WHY: Ensure only clean, validated data enters the database
    // HOW: Use mongoose ObjectId constructor and sanitized values
    const newlyCreatedAddress = new Address({
      userId: new mongoose.Types.ObjectId(userId),
      address: sanitizedAddress,
      city: sanitizedCity,
      pincode: sanitizedPincode,
      phone: sanitizedPhone,
      notes: sanitizedNotes,
    });

    await newlyCreatedAddress.save();

    res.status(201).json({
      success: true,
      data: newlyCreatedAddress,
    });
  } catch (e) {
    // SECURITY: Generic error handling to prevent information disclosure
    // WHY: Detailed error messages can reveal system internals to attackers
    // HOW: Log detailed errors internally but return generic messages to clients
    console.error("Error adding address:", e);
    res.status(500).json({
      success: false,
      message: "An error occurred while adding the address",
    });
  }
};

const fetchAllAddress = async (req, res) => {
  try {
    const { userId } = req.params;

    // SECURITY: Validate userId is provided
    // WHY: Prevent errors from missing parameters and ensure proper request structure
    // HOW: Check parameter existence before processing
    if (!userId) {
      return res.status(400).json({
        success: false,
        message: "User ID is required",
      });
    }

    // SECURITY: Validate userId is a valid ObjectId
    // WHY: Prevent NoSQL injection through URL parameters
    // HOW: Validate ObjectId format in route parameters
    if (!isValidObjectId(userId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid user ID format",
      });
    }

    // SECURITY: Authorization - Verify authenticated user matches userId
    // WHY: Prevent IDOR vulnerability - users accessing other users' addresses
    // HOW: Compare authenticated user with requested userId from parameters
    if (req.user && req.user.id !== userId) {
      return res.status(403).json({
        success: false,
        message: "Unauthorized: Cannot access addresses of another user",
      });
    }

    // SECURITY: Use ObjectId for query to prevent injection
    // WHY: Ensure type-safe database queries that prevent operator injection
    // HOW: Convert string parameters to ObjectId in database queries
    const addressList = await Address.find({
      userId: new mongoose.Types.ObjectId(userId),
    }).select("-__v"); // SECURITY: Exclude internal version field

    res.status(200).json({
      success: true,
      data: addressList,
    });
  } catch (e) {
    console.error("Error fetching addresses:", e);
    res.status(500).json({
      success: false,
      message: "An error occurred while fetching addresses",
    });
  }
};

const editAddress = async (req, res) => {
  try {
    const { userId, addressId } = req.params;
    const { address, city, pincode, phone, notes } = req.body;

    // SECURITY: Validate required parameters
    // WHY: Ensure all necessary identifiers are present for the operation
    // HOW: Check both userId and addressId parameters exist
    if (!userId || !addressId) {
      return res.status(400).json({
        success: false,
        message: "User ID and Address ID are required",
      });
    }

    // SECURITY: Validate ObjectId formats
    // WHY: Prevent NoSQL injection through malformed IDs in URL parameters
    // HOW: Validate both userId and addressId as proper ObjectIds
    if (!isValidObjectId(userId) || !isValidObjectId(addressId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid ID format",
      });
    }

    // SECURITY: Authorization - Verify authenticated user matches userId
    // WHY: Prevent users from editing addresses belonging to other users
    // HOW: Enforce ownership through JWT token comparison
    if (req.user && req.user.id !== userId) {
      return res.status(403).json({
        success: false,
        message: "Unauthorized: Cannot edit address of another user",
      });
    }

    // SECURITY: Build update object with only allowed fields (prevent mass assignment)
    // WHY: Prevent attackers from updating fields they shouldn't (like userId, _id, etc.)
    // HOW: Explicitly define which fields can be updated and validate each one
    const updateData = {};

    if (address !== undefined) {
      const sanitizedAddress = sanitizeInput(address);
      if (!validateLength(sanitizedAddress, 5, 200)) {
        return res.status(400).json({
          success: false,
          message: "Address must be between 5 and 200 characters",
        });
      }
      updateData.address = sanitizedAddress;
    }

    if (city !== undefined) {
      const sanitizedCity = sanitizeInput(city);
      if (!validateLength(sanitizedCity, 2, 50)) {
        return res.status(400).json({
          success: false,
          message: "City must be between 2 and 50 characters",
        });
      }
      updateData.city = sanitizedCity;
    }

    if (pincode !== undefined) {
      const sanitizedPincode = sanitizeInput(pincode);
      if (!validatePincode(sanitizedPincode)) {
        return res.status(400).json({
          success: false,
          message: "Pincode must be 4-10 digits",
        });
      }
      updateData.pincode = sanitizedPincode;
    }

    if (phone !== undefined) {
      const sanitizedPhone = sanitizeInput(phone);
      if (!validatePhone(sanitizedPhone)) {
        return res.status(400).json({
          success: false,
          message: "Invalid phone number format",
        });
      }
      updateData.phone = sanitizedPhone;
    }

    if (notes !== undefined) {
      const sanitizedNotes = sanitizeInput(notes);
      if (sanitizedNotes.length > 500) {
        return res.status(400).json({
          success: false,
          message: "Notes must not exceed 500 characters",
        });
      }
      updateData.notes = sanitizedNotes;
    }

    // SECURITY: Ensure at least one field is being updated
    // WHY: Prevent unnecessary database operations and ensure valid update requests
    // HOW: Check if update object contains any fields after validation
    if (Object.keys(updateData).length === 0) {
      return res.status(400).json({
        success: false,
        message: "No valid fields to update",
      });
    }

    // SECURITY: Use ObjectIds and verify ownership in query
    // WHY: Ensure the address belongs to the user before updating (defense in depth)
    // HOW: Include both addressId and userId in the query condition
    const updatedAddress = await Address.findOneAndUpdate(
      {
        _id: new mongoose.Types.ObjectId(addressId),
        userId: new mongoose.Types.ObjectId(userId), // SECURITY: Double ownership verification
      },
      updateData,
      { new: true, runValidators: true } // SECURITY: Run schema validators on update
    ).select("-__v");

    if (!updatedAddress) {
      return res.status(404).json({
        success: false,
        message: "Address not found or unauthorized", // SECURITY: Generic message
      });
    }

    res.status(200).json({
      success: true,
      data: updatedAddress,
    });
  } catch (e) {
    console.error("Error updating address:", e);
    res.status(500).json({
      success: false,
      message: "An error occurred while updating the address",
    });
  }
};

const deleteAddress = async (req, res) => {
  try {
    const { userId, addressId } = req.params;

    // SECURITY: Validate required parameters
    // WHY: Ensure proper identifiers for deletion operation
    // HOW: Verify both userId and addressId are provided
    if (!userId || !addressId) {
      return res.status(400).json({
        success: false,
        message: "User ID and Address ID are required",
      });
    }

    // SECURITY: Validate ObjectId formats
    // WHY: Prevent NoSQL injection in deletion operations
    // HOW: Validate ObjectId format before database operation
    if (!isValidObjectId(userId) || !isValidObjectId(addressId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid ID format",
      });
    }

    // SECURITY: Authorization - Verify authenticated user matches userId
    // WHY: Prevent users from deleting addresses of other users
    // HOW: Enforce ownership through authentication token
    if (req.user && req.user.id !== userId) {
      return res.status(403).json({
        success: false,
        message: "Unauthorized: Cannot delete address of another user",
      });
    }

    // SECURITY: Use ObjectIds and verify ownership in query
    // WHY: Ensure the address belongs to the user before deletion
    // HOW: Include ownership check directly in the database query
    const deletedAddress = await Address.findOneAndDelete({
      _id: new mongoose.Types.ObjectId(addressId),
      userId: new mongoose.Types.ObjectId(userId), // SECURITY: Ownership verification
    });

    if (!deletedAddress) {
      return res.status(404).json({
        success: false,
        message: "Address not found or unauthorized", // SECURITY: Don't distinguish between not found and unauthorized
      });
    }

    res.status(200).json({
      success: true,
      message: "Address deleted successfully",
    });
  } catch (e) {
    console.error("Error deleting address:", e);
    res.status(500).json({
      success: false,
      message: "An error occurred while deleting the address",
    });
  }
};

module.exports = { addAddress, editAddress, fetchAllAddress, deleteAddress };