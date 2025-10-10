const express = require("express");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const helmet = require("helmet");
const helmetCsp = require("helmet-csp");
const csurf = require("csurf");

// Load environment variables FIRST before any other imports
require('dotenv').config();

// Now import other modules
const passport = require("./config/passport");
const authRouter = require("./routes/auth/auth-routes");
const adminProductsRouter = require("./routes/admin/products-routes");
const adminOrderRouter = require("./routes/admin/order-routes");

const shopProductsRouter = require("./routes/shop/products-routes");
const shopCartRouter = require("./routes/shop/cart-routes");
const shopAddressRouter = require("./routes/shop/address-routes");
const shopOrderRouter = require("./routes/shop/order-routes");
const shopSearchRouter = require("./routes/shop/search-routes");
const shopReviewRouter = require("./routes/shop/review-routes");

const commonFeatureRouter = require("./routes/common/feature-routes");

// Debug: Check if environment variables are loaded
console.log("Google Client ID:", process.env.GOOGLE_CLIENT_ID ? "Loaded" : "Missing");
console.log("Google Client Secret:", process.env.GOOGLE_CLIENT_SECRET ? "Loaded" : "Missing");

mongoose
  .connect("mongodb+srv://thakshilafonseka2002:LHkyYBaSwXbNUzVb@cluster0.jal2xrl.mongodb.net/")
  .then(() => console.log("MongoDB connected"))
  .catch((error) => console.log(error));

const app = express();
const PORT = process.env.PORT || 5000;

// Secure HTTP headers
app.use(helmet());
// Content Security Policy
app.use(helmetCsp({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://apis.google.com"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:", "https:"],
    connectSrc: ["'self'", "https://accounts.google.com"],
    fontSrc: ["'self'", "https:"],
    objectSrc: ["'none'"],
    upgradeInsecureRequests: [],
  },
}));
// HTTPS redirect in production
if (process.env.NODE_ENV === 'production') {
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] !== 'https') {
      return res.redirect('https://' + req.headers.host + req.url);
    }
    next();
  });
}

// Initialize Passport
app.use(passport.initialize());

app.use(
  cors({
    origin: "http://localhost:5173",
    methods: ["GET", "POST", "DELETE", "PUT"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "Cache-Control",
      "Expires",
      "Pragma",
      "XSRF-TOKEN"
    ],
    credentials: true,
  })
);

app.use(cookieParser());
app.use(express.json());

// CSRF protection for state-changing requests
app.use(csurf({ cookie: true }));

// CSRF token endpoint for frontend to fetch token
app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

app.use("/api/auth", authRouter);
app.use("/api/admin/products", adminProductsRouter);
app.use("/api/admin/orders", adminOrderRouter);

app.use("/api/shop/products", shopProductsRouter);
app.use("/api/shop/cart", shopCartRouter);
app.use("/api/shop/address", shopAddressRouter);
app.use("/api/shop/order", shopOrderRouter);
app.use("/api/shop/search", shopSearchRouter);
app.use("/api/shop/review", shopReviewRouter);

app.use("/api/common/feature", commonFeatureRouter);

// Error handler for CSRF errors
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ success: false, message: 'Invalid CSRF token' });
  }
  next(err);
});

app.listen(PORT, () => console.log(`Server is now running on port ${PORT}`));