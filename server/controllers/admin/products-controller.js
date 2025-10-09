const { imageUploadUtil } = require("../../helpers/cloudinary")
const Product = require("../../models/Product")
const mongoose = require("mongoose")

// Security: Sanitize filename to prevent command injection
const sanitizeFilename = (filename) => {
  if (!filename) return "upload"
  
  // Remove path traversal attempts and special characters
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
    .replace(/\)/g, "") // Remove parentheses
  
  // Remove any non-alphanumeric characters except hyphens, underscores, and dots
  sanitized = sanitized.replace(/[^a-zA-Z0-9\-_.]/g, "")
  
  // Ensure the filename has a safe extension
  const parts = sanitized.split('.')
  if (parts.length > 1) {
    const extension = parts.pop().toLowerCase()
    const allowedExtensions = ['jpg', 'jpeg', 'png', 'gif', 'webp']
    if (!allowedExtensions.includes(extension)) {
      // If extension is not allowed, remove it and add a safe one
      return parts.join('') + '.jpg'
    }
  }
  
  // Limit filename length
  if (sanitized.length > 100) {
    sanitized = sanitized.substring(0, 100)
  }
  
  return sanitized || "upload"
}

const handleImageUpload = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: "No file uploaded",
      })
    }

    // SECURITY: Validate and sanitize original filename if it exists
    if (req.file.originalname) {
      req.file.originalname = sanitizeFilename(req.file.originalname)
    }

    // Validate file type (only allow images)
    const allowedMimeTypes = ["image/jpeg", "image/png", "image/gif", "image/webp"]
    if (!allowedMimeTypes.includes(req.file.mimetype)) {
      return res.status(400).json({
        success: false,
        message: "Invalid file type. Only JPEG, PNG, GIF, and WebP images are allowed",
      })
    }

    // Validate file size (max 5MB)
    const maxSize = 5 * 1024 * 1024 // 5MB
    if (req.file.size > maxSize) {
      return res.status(400).json({
        success: false,
        message: "File size too large. Maximum size is 5MB",
      })
    }

    // SECURITY: Generate a safe filename for the upload
    const safeFilename = sanitizeFilename(req.file.originalname) || `image_${Date.now()}`
    
    const b64 = Buffer.from(req.file.buffer).toString("base64")
    const url = "data:" + req.file.mimetype + ";base64," + b64
    
    // SECURITY: Pass safe filename to the upload utility
    // Note: You may need to modify imageUploadUtil to accept a safe filename parameter
    const result = await imageUploadUtil(url, safeFilename)

    res.json({
      success: true,
      result,
    })
  } catch (error) {
    console.log("File upload error:", error)
    res.status(500).json({
      success: false,
      message: "Error occurred during file upload",
    })
  }
}

//add a new product
const addProduct = async (req, res) => {
  try {
    const { image, title, description, category, brand, price, salePrice, totalStock, averageReview } = req.body

    if (!title || !description || !category || !brand) {
      return res.status(400).json({
        success: false,
        message: "Required fields are missing",
      })
    }

    // Validate numeric fields
    const priceNum = Number.parseFloat(price)
    const salePriceNum = Number.parseFloat(salePrice)
    const totalStockNum = Number.parseInt(totalStock)

    if (isNaN(priceNum) || priceNum < 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid price value",
      })
    }

    if (isNaN(salePriceNum) || salePriceNum < 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid sale price value",
      })
    }

    if (isNaN(totalStockNum) || totalStockNum < 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid stock value",
      })
    }

    console.log(averageReview, "averageReview")

    const newlyCreatedProduct = new Product({
      image,
      title,
      description,
      category,
      brand,
      price: priceNum,
      salePrice: salePriceNum,
      totalStock: totalStockNum,
      averageReview,
    })

    await newlyCreatedProduct.save()
    res.status(201).json({
      success: true,
      data: newlyCreatedProduct,
    })
  } catch (e) {
    console.log(e)
    res.status(500).json({
      success: false,
      message: "Error occured",
    })
  }
}

//fetch all products
const fetchAllProducts = async (req, res) => {
  try {
    const listOfProducts = await Product.find({})
    res.status(200).json({
      success: true,
      data: listOfProducts,
    })
  } catch (e) {
    console.log(e)
    res.status(500).json({
      success: false,
      message: "Error occured",
    })
  }
}

//edit a product
const editProduct = async (req, res) => {
  try {
    const { id } = req.params

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid product ID format",
      })
    }

    const { image, title, description, category, brand, price, salePrice, totalStock, averageReview } = req.body

    const findProduct = await Product.findById(id)
    if (!findProduct)
      return res.status(404).json({
        success: false,
        message: "Product not found",
      })

    if (price !== undefined && price !== "") {
      const priceNum = Number.parseFloat(price)
      if (isNaN(priceNum) || priceNum < 0) {
        return res.status(400).json({
          success: false,
          message: "Invalid price value",
        })
      }
      findProduct.price = priceNum
    }

    if (salePrice !== undefined && salePrice !== "") {
      const salePriceNum = Number.parseFloat(salePrice)
      if (isNaN(salePriceNum) || salePriceNum < 0) {
        return res.status(400).json({
          success: false,
          message: "Invalid sale price value",
        })
      }
      findProduct.salePrice = salePriceNum
    }

    if (totalStock !== undefined) {
      const totalStockNum = Number.parseInt(totalStock)
      if (isNaN(totalStockNum) || totalStockNum < 0) {
        return res.status(400).json({
          success: false,
          message: "Invalid stock value",
        })
      }
      findProduct.totalStock = totalStockNum
    }

    findProduct.title = title || findProduct.title
    findProduct.description = description || findProduct.description
    findProduct.category = category || findProduct.category
    findProduct.brand = brand || findProduct.brand
    findProduct.image = image || findProduct.image
    findProduct.averageReview = averageReview || findProduct.averageReview

    await findProduct.save()
    res.status(200).json({
      success: true,
      data: findProduct,
    })
  } catch (e) {
    console.log(e)
    res.status(500).json({
      success: false,
      message: "Error occured",
    })
  }
}

//delete a product
const deleteProduct = async (req, res) => {
  try {
    const { id } = req.params

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid product ID format",
      })
    }

    const product = await Product.findByIdAndDelete(id)

    if (!product)
      return res.status(404).json({
        success: false,
        message: "Product not found",
      })

    res.status(200).json({
      success: true,
      message: "Product delete successfully",
    })
  } catch (e) {
    console.log(e)
    res.status(500).json({
      success: false,
      message: "Error occured",
    })
  }
}

module.exports = {
  handleImageUpload,
  addProduct,
  fetchAllProducts,
  editProduct,
  deleteProduct,
}