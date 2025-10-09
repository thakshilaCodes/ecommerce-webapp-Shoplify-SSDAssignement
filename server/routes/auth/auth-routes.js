const express = require("express");
const passport = require("../../config/passport");
const {
  registerUser,
  loginUser,
  logoutUser,
  authMiddleware,
  googleAuthCallback,
  getCurrentUser,
} = require("../../controllers/auth/auth-controller");

const router = express.Router();

// Local authentication
router.post("/register", registerUser);
router.post("/login", loginUser);
router.post("/logout", logoutUser);

// Google OAuth routes
router.get(
  "/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

router.get(
  "/google/callback",
  passport.authenticate("google", {
    failureRedirect: "http://localhost:5173/login?error=auth_failed",
    session: false, // We're using JWT, not sessions
  }),
  googleAuthCallback
);

// Auth check route
router.get("/check-auth", authMiddleware, getCurrentUser);

module.exports = router;