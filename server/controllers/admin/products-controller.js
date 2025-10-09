const { imageUploadUtil } = require("../../helpers/cloudinary");
const Product = require("../../models/Product");
const mongoose = require("mongoose");

// WHY: Prevent command injection and path traversal in filenames
// HOW: Remove dangerous characters and validate file extensions
const sanitizeFilename = (filename) => {
  if (!filename) return "upload";
  
  let sanitized = filename
    .replace(/\.\./g, "") // Remove path traversal
    .replace(/\//g, "") // Remove slashes
    .replace(/\\/g, "") // Remove backslashes
    .replace(/\|/g, "") // Remove pipes
    .replace(/&/g, "") // Remove ampersands
    .replace(/;/g, "") // Remove semicolons
    .replace(/\$/g, "") // Remove dollar signs
    .replace(/`/g, "") // Remove backticks
    .replace(/\(/g, "") // Remove parentheses
    .replace(/\)/g, ""); // Remove parentheses
  
  sanitized = sanitized.replace(/[^a-zA-Z0-9\-_.]/g, "");
  
  const parts = sanitized.split('.');
  if (parts.length > 1) {
    const extension = parts.pop().toLowerCase();
    const allowedExtensions = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
    if (!allowedExtensions.includes(extension)) {
      return parts.join('') + '.jpg';
    }
  }
  
  if (sanitized.length > 100) {
    sanitized = sanitized.substring(0, 100);
  }
  
  return sanitized || "upload";
};

// WHY: Prevent XSS attacks through text inputs
// HOW: Remove HTML tags and dangerous characters from string inputs
const sanitizeTextInput = (input) => {
  if (typeof input !== "string") return input;
  return input
    .replace(/[<>{}$\\]/g, "") // Remove dangerous characters
    .trim();
};

// WHY: Prevent injection of arbitrary category values
// HOW: Validate against whitelist of allowed categories
const isValidCategory = (category) => {
  const allowedCategories = ["men", "women", "kids", "accessories", "footwear"];
  return allowedCategories.includes(category.toLowerCase());
};

const handleImageUpload = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: "No file uploaded",
      });
    }

    // WHY: Prevent malicious file uploads
    // HOW: Validate and sanitize filename
    if (req.file.originalname) {
      req.file.originalname = sanitizeFilename(req.file.originalname);
    }

    // WHY: Prevent non-image files from being uploaded
    // HOW: Whitelist allowed MIME types
    const allowedMimeTypes = ["image/jpeg", "image/png", "image/gif", "image/webp"];
    if (!allowedMimeTypes.includes(req.file.mimetype)) {
      return res.status(400).json({
        success: false,
        message: "Invalid file type. Only JPEG, PNG, GIF, and WebP images are allowed",
      });
    }

    // WHY: Prevent DoS through large file uploads
    // HOW: Limit file size to 5MB
    const maxSize = 5 * 1024 * 1024;
    if (req.file.size > maxSize) {
      return res.status(400).json({
        success: false,
        message: "File size too large. Maximum size is 5MB",
      });
    }

    const safeFilename = sanitizeFilename(req.file.originalname) || `image_${Date.now()}`;
    
    const b64 = Buffer.from(req.file.buffer).toString("base64");
    const url = "data:" + req.file.mimetype + ";base64," + b64;
    
    const result = await imageUploadUtil(url, safeFilename);

    res.json({
      success: true,
      result,
    });
  } catch (error) {
    console.log("File upload error:", error);
    res.status(500).json({
      success: false,
      message: "Error occurred during file upload",
    });
  }
};

// WHY: Original code didn't sanitize text inputs, allowing XSS attacks
// HOW: Sanitize all string inputs and validate all fields
const addProduct = async (req, res) => {
  try {
    const { image, title, description, category, brand, price, salePrice, totalStock, averageReview } = req.body;

    if (!title || !description || !category || !brand) {
      return res.status(400).json({
        success: false,
        message: "Required fields are missing",
      });
    }

    // WHY: Prevent XSS attacks through text fields
    // HOW: Sanitize all string inputs
    const sanitizedTitle = sanitizeTextInput(title);
    const sanitizedDescription = sanitizeTextInput(description);
    const sanitizedCategory = sanitizeTextInput(category);
    const sanitizedBrand = sanitizeTextInput(brand);
    const sanitizedImage = sanitizeTextInput(image);

    // WHY: Validate string lengths to prevent database issues
    // HOW: Check min/max lengths
    if (sanitizedTitle.length < 3 || sanitizedTitle.length > 200) {
      return res.status(400).json({
        success: false,
        message: "Title must be between 3 and 200 characters",
      });
    }

    if (sanitizedDescription.length < 10 || sanitizedDescription.length > 2000) {
      return res.status(400).json({
        success: false,
        message: "Description must be between 10 and 2000 characters",
      });
    }

    // WHY: Prevent injection of arbitrary category values
    // HOW: Validate against whitelist
    if (!isValidCategory(sanitizedCategory)) {
      return res.status(400).json({
        success: false,
        message: "Invalid category. Allowed: men, women, kids, accessories, footwear",
      });
    }

    // WHY: Validate numeric inputs to prevent injection
    // HOW: Parse and validate ranges
    const priceNum = Number.parseFloat(price);
    const salePriceNum = Number.parseFloat(salePrice);
    const totalStockNum = Number.parseInt(totalStock);

    if (isNaN(priceNum) || priceNum < 0 || priceNum > 10000000) {
      return res.status(400).json({
        success: false,
        message: "Invalid price value",
      });
    }

    if (isNaN(salePriceNum) || salePriceNum < 0 || salePriceNum > 10000000) {
      return res.status(400).json({
        success: false,
        message: "Invalid sale price value",
      });
    }

    if (salePriceNum >= priceNum) {
      return res.status(400).json({
        success: false,
        message: "Sale price must be less than regular price",
      });
    }

    if (isNaN(totalStockNum) || totalStockNum < 0 || totalStockNum > 1000000) {
      return res.status(400).json({
        success: false,
        message: "Invalid stock value",
      });
    }

    console.log(averageReview, "averageReview");

    // WHY: Use sanitized and validated data
    // HOW: Create product with clean inputs
    const newlyCreatedProduct = new Product({
      image: sanitizedImage,
      title: sanitizedTitle,
      description: sanitizedDescription,
      category: sanitizedCategory.toLowerCase(),
      brand: sanitizedBrand,
      price: priceNum,
      salePrice: salePriceNum,
      totalStock: totalStockNum,
      averageReview,
    });

    await newlyCreatedProduct.save();
    res.status(201).json({
      success: true,
      data: newlyCreatedProduct,
    });
  } catch (e) {
    console.log(e);
    res.status(500).json({
      success: false,
      message: "Error occured",
    });
  }
};

// WHY: Prevent DoS attacks through unlimited result sets
// HOW: Add pagination with limits
const fetchAllProducts = async (req, res) => {
  try {
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const skip = (page - 1) * limit;

    const listOfProducts = await Product.find({})
      .sort({ createdAt: -1 })
      .limit(limit)
      .skip(skip)
      .select("-__v")
      .lean();

    const totalProducts = await Product.countDocuments({});

    res.status(200).json({
      success: true,
      data: listOfProducts,
      pagination: {
        total: totalProducts,
        page,
        limit,
        pages: Math.ceil(totalProducts / limit),
      },
    });
  } catch (e) {
    console.log(e);
    res.status(500).json({
      success: false,
      message: "Error occured",
    });
  }
};

// WHY: Original code allowed mass assignment of any field
// HOW: Sanitize inputs, validate fields, and only update allowed fields
const editProduct = async (req, res) => {
  try {
    const { id } = req.params;

    // WHY: Prevent NoSQL injection through invalid ObjectId
    // HOW: Validate ObjectId format
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid product ID format",
      });
    }

    const { image, title, description, category, brand, price, salePrice, totalStock, averageReview } = req.body;

    const findProduct = await Product.findById(id);
    if (!findProduct)
      return res.status(404).json({
        success: false,
        message: "Product not found",
      });

    // WHY: Prevent XSS through text inputs
    // HOW: Sanitize and validate all string fields
    if (title !== undefined) {
      const sanitizedTitle = sanitizeTextInput(title);
      if (sanitizedTitle.length < 3 || sanitizedTitle.length > 200) {
        return res.status(400).json({
          success: false,
          message: "Title must be between 3 and 200 characters",
        });
      }
      findProduct.title = sanitizedTitle;
    }

    if (description !== undefined) {
      const sanitizedDescription = sanitizeTextInput(description);
      if (sanitizedDescription.length < 10 || sanitizedDescription.length > 2000) {
        return res.status(400).json({
          success: false,
          message: "Description must be between 10 and 2000 characters",
        });
      }
      findProduct.description = sanitizedDescription;
    }

    if (category !== undefined) {
      const sanitizedCategory = sanitizeTextInput(category);
      if (!isValidCategory(sanitizedCategory)) {
        return res.status(400).json({
          success: false,
          message: "Invalid category",
        });
      }
      findProduct.category = sanitizedCategory.toLowerCase();
    }

    if (brand !== undefined) {
      const sanitizedBrand = sanitizeTextInput(brand);
      if (sanitizedBrand.length < 2 || sanitizedBrand.length > 100) {
        return res.status(400).json({
          success: false,
          message: "Brand must be between 2 and 100 characters",
        });
      }
      findProduct.brand = sanitizedBrand;
    }

    if (image !== undefined) {
      findProduct.image = sanitizeTextInput(image);
    }

    // WHY: Validate numeric fields to prevent injection
    // HOW: Parse and validate ranges
    if (price !== undefined && price !== "") {
      const priceNum = Number.parseFloat(price);
      if (isNaN(priceNum) || priceNum < 0 || priceNum > 10000000) {
        return res.status(400).json({
          success: false,
          message: "Invalid price value",
        });
      }
      findProduct.price = priceNum;
    }

    if (salePrice !== undefined && salePrice !== "") {
      const salePriceNum = Number.parseFloat(salePrice);
      if (isNaN(salePriceNum) || salePriceNum < 0 || salePriceNum > 10000000) {
        return res.status(400).json({
          success: false,
          message: "Invalid sale price value",
        });
      }
      if (salePriceNum >= findProduct.price) {
        return res.status(400).json({
          success: false,
          message: "Sale price must be less than regular price",
        });
      }
      findProduct.salePrice = salePriceNum;
    }

    if (totalStock !== undefined) {
      const totalStockNum = Number.parseInt(totalStock);
      if (isNaN(totalStockNum) || totalStockNum < 0 || totalStockNum > 1000000) {
        return res.status(400).json({
          success: false,
          message: "Invalid stock value",
        });
      }
      findProduct.totalStock = totalStockNum;
    }

    if (averageReview !== undefined) {
      const reviewNum = Number.parseFloat(averageReview);
      if (isNaN(reviewNum) || reviewNum < 0 || reviewNum > 5) {
        return res.status(400).json({
          success: false,
          message: "Invalid review value (must be 0-5)",
        });
      }
      findProduct.averageReview = reviewNum;
    }

    await findProduct.save();
    res.status(200).json({
      success: true,
      data: findProduct,
    });
  } catch (e) {
    console.log(e);
    res.status(500).json({
      success: false,
      message: "Error occured",
    });
  }
};

const deleteProduct = async (req, res) => {
  try {
    const { id } = req.params;

    // WHY: Prevent NoSQL injection through invalid ObjectId
    // HOW: Validate ObjectId format before deletion
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid product ID format",
      });
    }

    const product = await Product.findByIdAndDelete(id);

    if (!product)
      return res.status(404).json({
        success: false,
        message: "Product not found",
      });

    res.status(200).json({
      success: true,
      message: "Product delete successfully",
    });
  } catch (e) {
    console.log(e);
    res.status(500).json({
      success: false,
      message: "Error occured",
    });
  }
};

module.exports = {
  handleImageUpload,
  addProduct,
  fetchAllProducts,
  editProduct,
  deleteProduct,
};