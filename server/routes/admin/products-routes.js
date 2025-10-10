const express = require("express");

const {
  handleImageUpload,
  addProduct,
  editProduct,
  fetchAllProducts,
  deleteProduct,
} = require("../../controllers/admin/products-controller");

const { upload } = require("../../helpers/cloudinary");
const { adminOnly } = require("../../middleware/roleCheck");
const { authMiddleware } = require("../../controllers/auth/auth-controller");

// WHY: Admin routes are completely unprotected, allowing anyone to add/edit/delete products
// HOW: Import authMiddleware and apply it to all admin routes
const { authMiddleware } = require("../../controllers/auth/auth-controller");

// WHY: Even authenticated users shouldn't access admin functions
// HOW: Create middleware to check if user has admin role
// Alternative approach in second code: uses centralized adminOnly middleware
const adminAuthMiddleware = (req, res, next) => {
  if (req.user && req.user.role === "admin") {
    next();
  } else {
    return res.status(403).json({
      success: false,
      message: "Access denied. Admin privileges required.",
    });
  }
};

// =========================
// Router Setup
// =========================
const router = express.Router();

// Apply authentication and authorization to all admin routes
// WHY: Protect routes from unauthorized access
// HOW: Use authMiddleware to check authentication, adminAuthMiddleware to check admin role
router.post(
  "/upload-image",
  authMiddleware,
  adminAuthMiddleware,
  upload.single("my_file"),
  handleImageUpload
);

router.post("/add", authMiddleware, adminAuthMiddleware, addProduct);
router.put("/edit/:id", authMiddleware, adminAuthMiddleware, editProduct);
router.delete("/delete/:id", authMiddleware, adminAuthMiddleware, deleteProduct);
router.get("/get", authMiddleware, adminAuthMiddleware, fetchAllProducts);

module.exports = router;
