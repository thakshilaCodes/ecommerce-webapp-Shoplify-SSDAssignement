const Product = require("../../models/Product");
const mongoose = require("mongoose");

// WHY: Prevent NoSQL injection attacks through query parameters
// HOW: Sanitize input by removing MongoDB operators and dangerous characters
const sanitizeInput = (input) => {
  if (typeof input !== "string") return input;
  // Remove NoSQL operators ($, {, }) and other dangerous characters
  return input
    .replace(/[{}$<>\\]/g, "")
    .trim();
};

// WHY: Prevent injection of arbitrary values in array parameters
// HOW: Validate each item is a string and sanitize it
const sanitizeArray = (arr) => {
  if (!Array.isArray(arr)) return [];
  return arr
    .filter((item) => typeof item === "string")
    .map((item) => sanitizeInput(item))
    .filter((item) => item.length > 0 && item.length <= 100);
};

// WHY: Prevent MongoDB ObjectId injection attacks
// HOW: Validate the ID format before using it in queries
const isValidObjectId = (id) => {
  return mongoose.Types.ObjectId.isValid(id);
};

// WHY: Original code accepted untrusted category/brand input directly in $in operator
// HOW: Sanitize and validate all filter inputs, add pagination, limit results
const getFilteredProducts = async (req, res) => {
  try {
    const { category = [], brand = [], sortBy = "price-lowtohigh" } = req.query;

    let filters = {};

    // WHY: Prevent NoSQL injection through category parameter
    // HOW: Split, sanitize each value, and validate against whitelist
    if (category.length) {
      const allowedCategories = ["men", "women", "kids", "accessories", "footwear"];
      const categoryArray = typeof category === "string" ? category.split(",") : [];
      const sanitizedCategories = sanitizeArray(categoryArray)
        .map(cat => cat.toLowerCase())
        .filter(cat => allowedCategories.includes(cat));
      
      if (sanitizedCategories.length > 0) {
        filters.category = { $in: sanitizedCategories };
      }
    }

    // WHY: Prevent NoSQL injection through brand parameter
    // HOW: Split, sanitize, and limit the number of brands to prevent DoS
    if (brand.length) {
      const brandArray = typeof brand === "string" ? brand.split(",") : [];
      const sanitizedBrands = sanitizeArray(brandArray).slice(0, 20); // Limit to 20 brands
      
      if (sanitizedBrands.length > 0) {
        filters.brand = { $in: sanitizedBrands };
      }
    }

    let sort = {};

    // WHY: Prevent injection of arbitrary sort parameters
    // HOW: Use whitelist of allowed sort values
    const allowedSortValues = [
      "price-lowtohigh",
      "price-hightolow",
      "title-atoz",
      "title-ztoa"
    ];
    
    const safeSortBy = allowedSortValues.includes(sortBy) ? sortBy : "price-lowtohigh";

    switch (safeSortBy) {
      case "price-lowtohigh":
        sort.price = 1;
        break;
      case "price-hightolow":
        sort.price = -1;
        break;
      case "title-atoz":
        sort.title = 1;
        break;
      case "title-ztoa":
        sort.title = -1;
        break;
      default:
        sort.price = 1;
        break;
    }

    // WHY: Prevent DoS attacks by limiting result size
    // HOW: Add pagination with maximum limit
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const limit = Math.min(parseInt(req.query.limit) || 50, 100); // Max 100 items
    const skip = (page - 1) * limit;

    // WHY: Use validated filters and add result limits
    // HOW: Apply limit, skip, and select only necessary fields
    const products = await Product.find(filters)
      .sort(sort)
      .limit(limit)
      .skip(skip)
      .select("-__v")
      .lean(); // Use lean() for better performance

    // Get total count for pagination info
    const totalProducts = await Product.countDocuments(filters);

    res.status(200).json({
      success: true,
      data: products,
      pagination: {
        total: totalProducts,
        page,
        limit,
        pages: Math.ceil(totalProducts / limit),
      },
    });
  } catch (e) {
    console.log("Error in getFilteredProducts:", e);
    res.status(500).json({
      success: false,
      message: "Some error occured",
    });
  }
};

// WHY: Original code didn't validate ObjectId format, allowing injection attempts
// HOW: Validate ID format before querying database
const getProductDetails = async (req, res) => {
  try {
    const { id } = req.params;

    // WHY: Prevent NoSQL injection through invalid ObjectId
    // HOW: Validate ObjectId format before using in query
    if (!isValidObjectId(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid product ID format",
      });
    }

    // WHY: Use validated ObjectId for secure query
    // HOW: Convert to ObjectId and exclude version field
    const product = await Product.findById(new mongoose.Types.ObjectId(id))
      .select("-__v")
      .lean();

    if (!product)
      return res.status(404).json({
        success: false,
        message: "Product not found!",
      });

    res.status(200).json({
      success: true,
      data: product,
    });
  } catch (e) {
    console.log("Error in getProductDetails:", e);
    res.status(500).json({
      success: false,
      message: "Some error occured",
    });
  }
};

module.exports = { getFilteredProducts, getProductDetails };