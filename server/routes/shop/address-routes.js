const express = require("express");

const {
  addAddress,
  fetchAllAddress,
  editAddress,
  deleteAddress,
} = require("../../controllers/shop/address-controller");

const { userOnly } = require("../../middleware/roleCheck");
const { authMiddleware } = require("../../controllers/auth/auth-controller");

const router = express.Router();

router.post("/add", authMiddleware, userOnly, addAddress);
router.get("/get/:userId", authMiddleware, userOnly, fetchAllAddress);
router.delete("/delete/:userId/:addressId", authMiddleware, userOnly, deleteAddress);
router.put("/update/:userId/:addressId", authMiddleware, userOnly, editAddress);

module.exports = router;