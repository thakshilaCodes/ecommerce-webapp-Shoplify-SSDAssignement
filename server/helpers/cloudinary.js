const cloudinary = require("cloudinary").v2;
const multer = require("multer");

// Cloudinary configuration
cloudinary.config({
  cloud_name: "dudmp1tnj",
  api_key: "662296399431226",
  api_secret: "HsWCxZ5mJ4Q7kRJVhgw3lhZfQvg",
});

// Multer memory storage configuration
const storage = new multer.memoryStorage();

// File validation constants
const ALLOWED_TYPES = ["image/jpeg", "image/png", "image/gif", "image/webp"];
const MAX_SIZE = 5 * 1024 * 1024; // 5MB

/**
 * Utility function to upload image to Cloudinary with validation
 * @param {Object} file - File object from multer (should have buffer, mimetype, and size)
 * @returns {Promise<Object>} Cloudinary upload result
 */
async function imageUploadUtil(file) {
  // Validate file object
  if (!file || !file.buffer || !file.mimetype || !file.size) {
    throw new Error("Invalid file upload.");
  }

  // Validate file type
  if (!ALLOWED_TYPES.includes(file.mimetype)) {
    throw new Error("Invalid file type. Only JPEG, PNG, GIF, and WEBP images are allowed.");
  }

  // Validate file size
  if (file.size > MAX_SIZE) {
    throw new Error("File too large. Maximum size is 5MB.");
  }

  // Convert buffer to base64 string for Cloudinary upload
  const fileStr = `data:${file.mimetype};base64,${file.buffer.toString("base64")}`;

  try {
    // Upload to Cloudinary
    const result = await cloudinary.uploader.upload(fileStr, {
      resource_type: "image"
    });
    return result;
  } catch (error) {
    throw new Error(`Upload failed: ${error.message}`);
  }
}

// Multer middleware configuration
const upload = multer({
  storage,
  limits: {
    fileSize: MAX_SIZE,
  },
  fileFilter: (req, file, cb) => {
    if (ALLOWED_TYPES.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error("Invalid file type. Only JPEG, PNG, GIF, and WEBP images are allowed."), false);
    }
  },
});

module.exports = { upload, imageUploadUtil };