const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../../models/User");

// Helper function to generate JWT token
const generateToken = (user) => {
  return jwt.sign(
    {
      id: user._id,
      role: user.role,
      email: user.email,
      userName: user.userName,
    },
    process.env.JWT_SECRET || "CLIENT_SECRET_KEY",
    { expiresIn: "60m" }
  );
};

// Register
const registerUser = async (req, res) => {
  const { userName, email, password } = req.body;

  try {
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
      return res.status(400).json({
        success: false,
        message: "User doesn't exist! Please register first",
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
      return res.status(400).json({
        success: false,
        message: "Incorrect password! Please try again",
      });
    }

    const token = generateToken(checkUser);

    res.cookie("token", token, { httpOnly: true, secure: false }).json({
      success: true,
      message: "Logged in successfully",
      user: {
        email: checkUser.email,
        role: checkUser.role,
        id: checkUser._id,
        userName: checkUser.userName,
      },
    });
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

    res.cookie("token", token, { 
      httpOnly: true, 
      secure: false,
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

    res.cookie("token", token, { 
      httpOnly: true, 
      secure: false,
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
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "CLIENT_SECRET_KEY");
    
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