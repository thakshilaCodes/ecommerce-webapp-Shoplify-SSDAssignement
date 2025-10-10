const Product = require("../../models/Product")

const searchProducts = async (req, res) => {
  try {
    const { keyword } = req.params

    // WHY: Prevent ReDoS (Regular Expression Denial of Service) and injection attacks
    // HOW: Validate input length, type, and escape special regex characters
    if (!keyword || typeof keyword !== "string") {
      return res.status(400).json({
        success: false,
        message: "Keyword is required and must be in string format",
      })
    }

    // Limit keyword length to prevent ReDoS attacks
    if (keyword.length > 100) {
      return res.status(400).json({
        success: false,
        message: "Search keyword is too long",
      })
    }

    // Escape special regex characters to prevent regex injection
    const escapeRegex = (str) => {
      return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
    }

    const sanitizedKeyword = escapeRegex(keyword.trim())

    // Additional check for empty string after trimming
    if (!sanitizedKeyword) {
      return res.status(400).json({
        success: false,
        message: "Search keyword cannot be empty",
      })
    }

    const regEx = new RegExp(sanitizedKeyword, "i")

    const createSearchQuery = {
      $or: [{ title: regEx }, { description: regEx }, { category: regEx }, { brand: regEx }],
    }

    // WHY: Unlimited results can cause memory issues and slow responses
    // HOW: Limit results to a reasonable number
    const searchResults = await Product.find(createSearchQuery).limit(100)

    res.status(200).json({
      success: true,
      data: searchResults,
    })
  } catch (error) {
    console.log(error)
    res.status(500).json({
      success: false,
      message: "Error",
    })
  }
}

module.exports = { searchProducts }
