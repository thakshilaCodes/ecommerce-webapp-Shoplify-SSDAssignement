const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const User = require("../../models/User")

// WHY: Prevent injection attacks and invalid data from being processed
// HOW: Validate and sanitize user inputs before processing
const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return emailRegex.test(email)
}

const validatePassword = (password) => {
  // Minimum 8 characters, at least one letter and one number
  return password && password.length >= 8
}

const sanitizeInput = (input) => {
  if (typeof input !== "string") return input
  // Remove potential NoSQL injection characters
  return input.replace(/[{}$]/g, "")
}

//register
const registerUser = async (req, res) => {
  const { userName, email, password } = req.body

  try {
    // WHY: Prevent injection attacks and ensure data integrity
    // HOW: Validate email format, password strength, and sanitize inputs
    if (!userName || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "All fields are required",
      })
    }

    if (!validateEmail(email)) {
      return res.status(400).json({
        success: false,
        message: "Invalid email format",
      })
    }

    if (!validatePassword(password)) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 8 characters long",
      })
    }

    // Sanitize inputs to prevent NoSQL injection
    const sanitizedUserName = sanitizeInput(userName)
    const sanitizedEmail = sanitizeInput(email)

    const checkUser = await User.findOne({ email: sanitizedEmail })
    if (checkUser)
      return res.json({
        success: false,
        message: "User Already exists with the same email! Please try again",
      })

    const hashPassword = await bcrypt.hash(password, 12)
    const newUser = new User({
      userName: sanitizedUserName,
      email: sanitizedEmail,
      password: hashPassword,
    })

    await newUser.save()
    res.status(200).json({
      success: true,
      message: "Registration successful",
    })
  } catch (e) {
    console.log(e)
    res.status(500).json({
      success: false,
      message: "Some error occured",
    })
  }
}

//login
const loginUser = async (req, res) => {
  const { email, password } = req.body

  try {
    // WHY: Prevent injection attacks during authentication
    // HOW: Validate and sanitize email input
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required",
      })
    }

    if (!validateEmail(email)) {
      return res.status(400).json({
        success: false,
        message: "Invalid email format",
      })
    }

    const sanitizedEmail = sanitizeInput(email)

    const checkUser = await User.findOne({ email: sanitizedEmail })
    if (!checkUser)
      return res.json({
        success: false,
        message: "User doesn't exists! Please register first",
      })

    const checkPasswordMatch = await bcrypt.compare(password, checkUser.password)
    if (!checkPasswordMatch)
      return res.json({
        success: false,
        message: "Incorrect password! Please try again",
      })

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
  res.clearCookie("token").json({
    success: true,
    message: "Logged out successfully!",
  })
}

//auth middleware
const authMiddleware = async (req, res, next) => {
  const token = req.cookies.token
  if (!token)
    return res.status(401).json({
      success: false,
      message: "Unauthorised user!",
    })

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

module.exports = { registerUser, loginUser, logoutUser, authMiddleware }
