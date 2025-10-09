const Product = require("../../models/Product")

const getFilteredProducts = async (req, res) => {
  try {
    const { category = [], brand = [], sortBy = "price-lowtohigh" } = req.query

    const filters = {}

    // WHY: Prevent NoSQL injection through query parameters
    // HOW: Validate input types and sanitize values
    if (category.length) {
      const categories = category
        .split(",")
        .map((c) => c.trim())
        .filter((c) => c.length > 0)
      // Limit number of categories to prevent query complexity attacks
      if (categories.length > 20) {
        return res.status(400).json({
          success: false,
          message: "Too many categories selected",
        })
      }
      filters.category = { $in: categories }
    }

    if (brand.length) {
      const brands = brand
        .split(",")
        .map((b) => b.trim())
        .filter((b) => b.length > 0)
      // Limit number of brands to prevent query complexity attacks
      if (brands.length > 20) {
        return res.status(400).json({
          success: false,
          message: "Too many brands selected",
        })
      }
      filters.brand = { $in: brands }
    }

    const sort = {}

    // WHY: Prevent injection of malicious sort parameters
    // HOW: Only allow predefined sort options
    const allowedSortOptions = ["price-lowtohigh", "price-hightolow", "title-atoz", "title-ztoa"]

    if (!allowedSortOptions.includes(sortBy)) {
      return res.status(400).json({
        success: false,
        message: "Invalid sort option",
      })
    }

    switch (sortBy) {
      case "price-lowtohigh":
        sort.price = 1
        break
      case "price-hightolow":
        sort.price = -1
        break
      case "title-atoz":
        sort.title = 1
        break
      case "title-ztoa":
        sort.title = -1
        break
      default:
        sort.price = 1
        break
    }

    const products = await Product.find(filters).sort(sort);

    res.status(200).json({
      success: true,
      data: products,
    })
  } catch (e) {
    console.log(e)
    res.status(500).json({
      success: false,
      message: "Some error occured",
    })
  }
}

const getProductDetails = async (req, res) => {
  try {
    const { id } = req.params

    // WHY: Invalid IDs can cause errors or be used for injection attacks
    // HOW: Check if the ID matches MongoDB ObjectId format
    const mongoose = require("mongoose")
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid product ID format",
      })
    }

    const product = await Product.findById(id)

    if (!product)
      return res.status(404).json({
        success: false,
        message: "Product not found!",
      })

    res.status(200).json({
      success: true,
      data: product,
    })
  } catch (e) {
    console.log(e)
    res.status(500).json({
      success: false,
      message: "Some error occured",
    })
  }
}

module.exports = { getFilteredProducts, getProductDetails }
