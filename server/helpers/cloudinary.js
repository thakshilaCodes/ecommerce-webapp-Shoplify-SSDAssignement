const cloudinary = require("cloudinary").v2;
const multer = require("multer");

cloudinary.config({
  cloud_name: "dudmp1tnj",
  api_key: "662296399431226",
  api_secret: "HsWCxZ5mJ4Q7kRJVhgw3lhZfQvg",
});

const storage = new multer.memoryStorage();


// Allowed image types and max size (5MB)
const ALLOWED_TYPES = ["image/jpeg", "image/png", "image/gif", "image/webp"];
const MAX_SIZE = 5 * 1024 * 1024;

async function imageUploadUtil(file) {
  // file can be a buffer or path, but multer provides req.file with mimetype and size
  if (!file || !file.mimetype || !file.size) {
    throw new Error("Invalid file upload.");
  }
  if (!ALLOWED_TYPES.includes(file.mimetype)) {
    throw new Error("Invalid file type. Only JPEG, PNG, GIF, and WEBP images are allowed.");
  }
  if (file.size > MAX_SIZE) {
    throw new Error("File too large. Maximum size is 5MB.");
  }
  // Upload from buffer
  const result = await cloudinary.uploader.upload_stream({
    resource_type: "image"
  }, (error, result) => {
    if (error) throw error;
    return result;
  });
  // Note: If using upload_stream, you need to pipe the buffer. If using upload(file.path), validate path.
  return result;
}

const upload = multer({ storage });

module.exports = { upload, imageUploadUtil };