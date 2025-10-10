const express = require("express");

const {
  addFeatureImage,
  getFeatureImages,
} = require("../../controllers/common/feature-controller");

const { adminOnly } = require("../../middleware/roleCheck");
const { authMiddleware } = require("../../controllers/auth/auth-controller");

const router = express.Router();

// Only admins can add feature images
router.post("/add", authMiddleware, adminOnly, addFeatureImage);
// Anyone can get feature images
router.get("/get", getFeatureImages);

module.exports = router;