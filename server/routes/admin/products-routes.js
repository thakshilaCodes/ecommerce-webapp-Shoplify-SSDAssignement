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

const router = express.Router();

// All admin routes require authentication and admin role
router.post("/upload-image", authMiddleware, adminOnly, upload.single("my_file"), handleImageUpload);
router.post("/add", authMiddleware, adminOnly, addProduct);
router.put("/edit/:id", authMiddleware, adminOnly, editProduct);
router.delete("/delete/:id", authMiddleware, adminOnly, deleteProduct);
router.get("/get", authMiddleware, adminOnly, fetchAllProducts);

module.exports = router;