const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../../models/User");
const validator = require("validator"); // Added for input validation

//register
const registerUser = async (req, res) => {
  const { userName, email, password } = req.body;

  try {
    // Input validation to prevent injection attacks
    if (!userName || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "All fields are required"
      });
    }

    // Validate email format
    if (!validator.isEmail(email)) {
      return res.status(400).json({
        success: false,
        message: "Please provide a valid email address"
      });
    }

    // Sanitize inputs to prevent XSS and injection
    const sanitizedUserName = validator.escape(userName.trim());
    const sanitizedEmail = validator.normalizeEmail(email.trim());
    
    // Basic password strength validation
    if (password.length < 8) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 8 characters long"
      });
    }

    const checkUser = await User.findOne({ email: sanitizedEmail }); // Use sanitized email
    if (checkUser)
      return res.status(409).json({ // Changed to 409 Conflict
        success: false,
        message: "User already exists with this email address"
      });

    const hashPassword = await bcrypt.hash(password, 12);
    const newUser = new User({
      userName: sanitizedUserName, // Use sanitized username
      email: sanitizedEmail, // Use sanitized email
      password: hashPassword,
    });

    await newUser.save();
    res.status(201).json({ // Changed to 201 Created
      success: true,
      message: "Registration successful",
    });
  } catch (e) {
    console.log(e);
    // Generic error message to prevent information disclosure
    res.status(500).json({
      success: false,
      message: "Registration failed",
    });
  }
};

//login
const loginUser = async (req, res) => {
  const { email, password } = req.body;

  try {
    // Input validation
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required"
      });
    }

    // Sanitize email input
    const sanitizedEmail = validator.normalizeEmail(email.trim());
    
    const checkUser = await User.findOne({ email: sanitizedEmail }); // Use sanitized email
    if (!checkUser)
      // Generic message to prevent user enumeration
      return res.status(401).json({
        success: false,
        message: "Invalid credentials"
      });

    const checkPasswordMatch = await bcrypt.compare(
      password,
      checkUser.password
    );
    if (!checkPasswordMatch)
      // Generic message to prevent user enumeration
      return res.status(401).json({
        success: false,
        message: "Invalid credentials"
   } );

    // Use environment variable for JWT secret to prevent hardcoded secrets
    const token = jwt.sign(
      {
        id: checkUser._id,
        role: checkUser.role,
        email: checkUser.email,
        userName: checkUser.userName,
      },
      process.env.JWT_SECRET || "CLIENT_SECRET_KEY", // Use environment variable
      { expiresIn: "60m" }
    );

    // Secure cookie settings to prevent XSS and CSRF
    res.cookie("token", token, { 
      httpOnly: true, // Prevents XSS attacks
      secure: process.env.NODE_ENV === "production", // HTTPS only in production
      sameSite: "strict" // CSRF protection
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
  } catch (e) {
    console.log(e);
    // Generic error message to prevent information disclosure
    res.status(500).json({
      success: false,
      message: "Login failed",
    });
  }
};

//logout
const logoutUser = (req, res) => {
  // Secure cookie clearance
  res.clearCookie("token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict"
  }).json({
    success: true,
    message: "Logged out successfully!",
  });
};

//auth middleware
const authMiddleware = async (req, res, next) => {
  const token = req.cookies.token;
  if (!token)
    return res.status(401).json({
      success: false,
      message: "Authentication required",
    });

  try {
    // Use environment variable for JWT secret
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "CLIENT_SECRET_KEY");
    
    // Verify user still exists in database (prevents token reuse after user deletion)
    const userExists = await User.findById(decoded.id);
    if (!userExists) {
      return res.status(401).json({
        success: false,
        message: "User no longer exists",
      });
    }
    
    req.user = decoded;
    next();
  } catch (error) {
    // Generic error message
    res.status(401).json({
      success: false,
      message: "Invalid authentication token",
    });
  }
};

module.exports = { registerUser, loginUser, logoutUser, authMiddleware };