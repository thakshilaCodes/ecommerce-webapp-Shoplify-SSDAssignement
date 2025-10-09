const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../../models/User");

// Password complexity check helper
function isPasswordComplex(password) {
  // At least 8 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special char
  const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]).{8,}$/;
  return regex.test(password);
}

//register
const registerUser = async (req, res) => {
  const { userName, email, password } = req.body;

  try {
    const checkUser = await User.findOne({ email });
    if (checkUser)
      return res.json({
        success: false,
        message: "User Already exists with the same email! Please try again",
      });

    if (!isPasswordComplex(password)) {
      return res.status(400).json({
        success: false,
        message:
          "Password must be at least 8 characters and include uppercase, lowercase, number, and special character.",
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
      message: "Some error occured",
    });
  }
};

// In-memory JWT blacklist (for demo; use persistent store in production)
const jwtBlacklist = new Set();

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes

const loginUser = async (req, res) => {
  const { email, password } = req.body;

  try {
    const checkUser = await User.findOne({ email });
    if (!checkUser)
      return res.json({
        success: false,
        message: "User doesn't exists! Please register first",
      });

    // Check for lockout
    if (checkUser.lockoutUntil && checkUser.lockoutUntil > Date.now()) {
      return res.json({
        success: false,
        message: `Account locked. Try again after ${new Date(checkUser.lockoutUntil).toLocaleTimeString()}`,
      });
    }

    const checkPasswordMatch = await bcrypt.compare(
      password,
      checkUser.password
    );
    if (!checkPasswordMatch) {
      checkUser.failedLoginAttempts = (checkUser.failedLoginAttempts || 0) + 1;
      if (checkUser.failedLoginAttempts >= MAX_FAILED_ATTEMPTS) {
        checkUser.lockoutUntil = Date.now() + LOCKOUT_TIME;
        await checkUser.save();
        return res.json({
          success: false,
          message: "Account locked due to too many failed attempts. Try again later.",
        });
      }
      await checkUser.save();
      return res.json({
        success: false,
        message: "Incorrect password! Please try again",
      });
    }

    // Reset failed attempts on successful login
    checkUser.failedLoginAttempts = 0;
    checkUser.lockoutUntil = null;
    await checkUser.save();

    const token = jwt.sign(
      {
        id: checkUser._id,
        role: checkUser.role,
        email: checkUser.email,
        userName: checkUser.userName,
      },
      "CLIENT_SECRET_KEY",
      { expiresIn: "60m" }
    );

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
      message: "Some error occured",
    });
  }
};

//logout
const logoutUser = (req, res) => {
  const token = req.cookies.token;
  if (token) {
    jwtBlacklist.add(token);
  }
  res.clearCookie("token").json({
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
      message: "Unauthorised user!",
    });

  // Check if token is blacklisted
  if (jwtBlacklist.has(token)) {
    return res.status(401).json({
      success: false,
      message: "Session expired. Please log in again.",
    });
  }

  try {
    const decoded = jwt.verify(token, "CLIENT_SECRET_KEY");
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({
      success: false,
      message: "Unauthorised user!",
    });
  }
};

module.exports = { registerUser, loginUser, logoutUser, authMiddleware };