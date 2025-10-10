const express = require("express");
const passport = require("../../config/passport");

const {
  registerUser,
  loginUser,
  logoutUser,
  authMiddleware,
  googleAuthCallback,
  facebookAuthCallback,
  getCurrentUser,
} = require("../../controllers/auth/auth-controller");

const authRateLimiter = require("../../middleware/authRateLimiter");

const router = express.Router();


// Local authentication with rate limiting
router.post("/register", authRateLimiter, registerUser);
router.post("/login", authRateLimiter, loginUser);
router.post("/logout", logoutUser);


// Google OAuth routes with rate limiting
router.get(
  "/google",
  authRateLimiter,
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

router.get(
  "/google/callback",
  authRateLimiter,
  passport.authenticate("google", {
    failureRedirect: "http://localhost:5173/login?error=auth_failed",
    session: false,
  }),
  googleAuthCallback
);


// Facebook OAuth routes with rate limiting
router.get(
  "/facebook",
  authRateLimiter,
  passport.authenticate("facebook", {
    scope: ["email"],
  })
);

router.get(
  "/facebook/callback",
  authRateLimiter,
  passport.authenticate("facebook", {
    failureRedirect: "http://localhost:5173/login?error=auth_failed",
    session: false,
  }),
  facebookAuthCallback
);

// Auth check route
router.get("/check-auth", authMiddleware, getCurrentUser);

module.exports = router;