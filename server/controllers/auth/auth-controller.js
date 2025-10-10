const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const validator = require("validator");
const User = require("../../models/User");
const { recordFailedLogin, isLocked, resetFailedLogins } = require("../../middleware/loginLockout");
const { blacklistToken, isTokenBlacklisted } = require("../../middleware/jwtBlacklist");


// Helper function to generate JWT token
const getJwtSecret = () => {
  if (!process.env.JWT_SECRET) {
    throw new Error("FATAL: JWT_SECRET environment variable is not set.");
  }
  return process.env.JWT_SECRET;
};

const generateToken = (user) => {
  // Short expiry for access token (15m)
  return jwt.sign(
    {
      id: user._id,
      role: user.role,
      email: user.email,
      userName: user.userName,
    },
    getJwtSecret(),
    { expiresIn: "15m" }
  );
};

// Register
const registerUser = async (req, res) => {
  const { userName, email, password } = req.body;

  try {
    // Password strength validation
    if (!validator.isStrongPassword(password, {
      minLength: 8,
      minLowercase: 1,
      minUppercase: 1,
      minNumbers: 1,
      minSymbols: 1
    })) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 8 characters and include uppercase, lowercase, number, and symbol."
      });
    }

    const checkUser = await User.findOne({ email });
    if (checkUser) {
      return res.status(400).json({
        success: false,
        message: "User already exists with the same email! Please try again",
      });
    }

    const hashPassword = await bcrypt.hash(password, 12);
    const newUser = new User({
      userName,
      email,
      password: hashPassword,
    });

    await newUser.save();
    res.status(200).json({
      success: true,
      message: "Registration successful",
    });
  } catch (e) {
    console.log(e);
    res.status(500).json({
      success: false,
      message: "Some error occurred",
    });
  }
};

// Login
const loginUser = async (req, res) => {
  const { email, password } = req.body;

  try {
    const checkUser = await User.findOne({ email });
    if (!checkUser) {
      recordFailedLogin(email);
      console.log(`[AUDIT] Failed login for non-existent user: ${email}`);
      return res.status(400).json({
        success: false,
        message: "User doesn't exist! Please register first",
      });
    }

    if (isLocked(email)) {
      console.log(`[AUDIT] Account locked due to failed logins: ${email}`);
      return res.status(403).json({
        success: false,
        message: "Account locked due to too many failed login attempts. Try again later."
      });
    }

    // Check if user registered with OAuth (no password)
    if ((checkUser.googleId || checkUser.facebookId) && !checkUser.password) {
      let provider = checkUser.googleId ? "Google" : "Facebook";
      return res.status(400).json({
        success: false,
        message: `This account uses ${provider} Sign-In. Please sign in with ${provider}.`,
      });
    }

    const checkPasswordMatch = await bcrypt.compare(
      password,
      checkUser.password
    );
    if (!checkPasswordMatch) {
      recordFailedLogin(email);
      console.log(`[AUDIT] Failed login (bad password) for: ${email}`);
      return res.status(400).json({
        success: false,
        message: "Incorrect password! Please try again",
      });
    }

    resetFailedLogins(email);
    const token = generateToken(checkUser);
    const isProd = process.env.NODE_ENV === 'production';
    res.cookie("token", token, {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? 'strict' : 'lax',
    }).json({
      success: true,
      message: "Logged in successfully",
      user: {
        email: checkUser.email,
        role: checkUser.role,
        id: checkUser._id,
        userName: checkUser.userName,
      },
    });
    console.log(`[AUDIT] Successful login: ${email}`);
  } catch (e) {
    console.log(e);
    res.status(500).json({
      success: false,
      message: "Some error occurred",
    });
  }
};

// Google OAuth Callback
const googleAuthCallback = async (req, res) => {
  try {
    const user = req.user;
    const token = generateToken(user);

    const isProd = process.env.NODE_ENV === 'production';
    res.cookie("token", token, {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? 'strict' : 'lax',
      maxAge: 60 * 60 * 1000 // 1 hour
    });

    res.redirect("http://localhost:5173");
  } catch (error) {
    console.error("Google OAuth callback error:", error);
    res.redirect("http://localhost:5173/login?error=auth_failed");
  }
};

// Facebook OAuth Callback
const facebookAuthCallback = async (req, res) => {
  try {
    const user = req.user;
    const token = generateToken(user);

    const isProd = process.env.NODE_ENV === 'production';
    res.cookie("token", token, {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? 'strict' : 'lax',
      maxAge: 60 * 60 * 1000 // 1 hour
    });

    res.redirect("http://localhost:5173");
  } catch (error) {
    console.error("Facebook OAuth callback error:", error);
    res.redirect("http://localhost:5173/login?error=auth_failed");
  }
};

// Get current user (for OAuth)
const getCurrentUser = (req, res) => {
  const user = req.user;
  res.status(200).json({
    success: true,
    message: "Authenticated user!",
    user: {
      id: user._id,
      userName: user.userName,
      email: user.email,
      role: user.role,
    },
  });
};

// Logout
const logoutUser = (req, res) => {
  const token = req.cookies.token;
  if (token) {
    blacklistToken(token);
    console.log(`[AUDIT] Token blacklisted on logout`);
  }
  res.clearCookie("token").json({
    success: true,
    message: "Logged out successfully!",
  });
};

// Auth middleware
const authMiddleware = async (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized user!",
    });
  }

  try {
    if (isTokenBlacklisted(token)) {
      return res.status(401).json({
        success: false,
        message: "Token is revoked. Please log in again.",
      });
    }
    const decoded = jwt.verify(token, getJwtSecret());
    const user = await User.findById(decoded.id).select("-password");
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User not found!",
      });
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({
      success: false,
      message: "Unauthorized user!",
    });
  }
};

module.exports = {
  registerUser,
  loginUser,
  logoutUser,
  authMiddleware,
  googleAuthCallback,
  facebookAuthCallback,
  getCurrentUser
};