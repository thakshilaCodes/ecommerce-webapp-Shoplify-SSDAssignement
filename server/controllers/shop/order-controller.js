const paypal = require("../../helpers/paypal")
const Order = require("../../models/Order")
const Cart = require("../../models/Cart")
const Product = require("../../models/Product")

const createOrder = async (req, res) => {
  try {
    const {
      userId,
      cartItems,
      addressInfo,
      orderStatus,
      paymentMethod,
      paymentStatus,
      totalAmount,
      orderDate,
      orderUpdateDate,
      paymentId,
      payerId,
      cartId,
    } = req.body

    // WHY: Prevent price manipulation and invalid order data
    // HOW: Validate required fields, recalculate total from cart items
    if (!userId || !cartItems || !Array.isArray(cartItems) || cartItems.length === 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid order data",
      })
    }

    // WHY: Users should only create orders for themselves
    // HOW: Check if the userId matches the authenticated user
    if (req.user.id !== userId) {
      return res.status(403).json({
        success: false,
        message: "Unauthorized: Cannot create order for another user",
      })
    }

    // WHY: Client-provided totals can be manipulated to pay less
    // HOW: Fetch actual product prices and calculate total on server
    let calculatedTotal = 0
    const validatedCartItems = []

    for (const item of cartItems) {
      const product = await Product.findById(item.productId)

      if (!product) {
        return res.status(400).json({
          success: false,
          message: `Product ${item.productId} not found`,
        })
      }

      // Check stock availability
      if (product.totalStock < item.quantity) {
        return res.status(400).json({
          success: false,
          message: `Insufficient stock for product: ${product.title}`,
        })
      }

      // Use server-side price, not client-provided price
      const itemPrice = product.salePrice > 0 ? product.salePrice : product.price
      calculatedTotal += itemPrice * item.quantity

      validatedCartItems.push({
        productId: item.productId,
        title: product.title,
        price: itemPrice,
        quantity: item.quantity,
      })
    }

    // Verify the total amount matches calculated total (with small tolerance for rounding)
    if (Math.abs(calculatedTotal - totalAmount) > 0.01) {
      return res.status(400).json({
        success: false,
        message: "Order total mismatch. Please refresh and try again.",
      })
    }

    const create_payment_json = {
      intent: "sale",
      payer: {
        payment_method: "paypal",
      },
      redirect_urls: {
        return_url: "http://localhost:5173/shop/paypal-return",
        cancel_url: "http://localhost:5173/shop/paypal-cancel",
      },
      transactions: [
        {
          item_list: {
            items: validatedCartItems.map((item) => ({
              name: item.title,
              sku: item.productId,
              price: item.price.toFixed(2),
              currency: "USD",
              quantity: item.quantity,
            })),
          },
          amount: {
            currency: "USD",
            total: calculatedTotal.toFixed(2),
          },
          description: "description",
        },
      ],
    }

    paypal.payment.create(create_payment_json, async (error, paymentInfo) => {
      if (error) {
        console.log(error)

        return res.status(500).json({
          success: false,
          message: "Error while creating paypal payment",
        })
      } else {
        const newlyCreatedOrder = new Order({
          userId,
          cartId,
          cartItems: validatedCartItems,
          addressInfo,
          orderStatus,
          paymentMethod,
          paymentStatus,
          totalAmount: calculatedTotal,
          orderDate,
          orderUpdateDate,
          paymentId,
          payerId,
        })

        await newlyCreatedOrder.save()

        const approvalURL = paymentInfo.links.find((link) => link.rel === "approval_url").href

        res.status(201).json({
          success: true,
          approvalURL,
          orderId: newlyCreatedOrder._id,
        })
      }
    })
  } catch (e) {
    console.log(e)
    res.status(500).json({
      success: false,
      message: "Some error occured!",
    })
  }
}

const capturePayment = async (req, res) => {
  try {
    const { paymentId, payerId, orderId } = req.body

    // WHY: Prevent invalid ID formats
    // HOW: Check ObjectId validity
    const mongoose = require("mongoose")
    if (!mongoose.Types.ObjectId.isValid(orderId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid order ID format",
      })
    }

    const order = await Order.findById(orderId)

    if (!order) {
      return res.status(404).json({
        success: false,
        message: "Order can not be found",
      })
    }

    // WHY: Users should only capture payments for their own orders
    // HOW: Check if the order belongs to the authenticated user
    if (req.user.id !== order.userId.toString()) {
      return res.status(403).json({
        success: false,
        message: "Unauthorized: Cannot capture payment for another user's order",
      })
    }

    order.paymentStatus = "paid"
    order.orderStatus = "confirmed"
    order.paymentId = paymentId
    order.payerId = payerId

    for (const item of order.cartItems) {
      const product = await Product.findById(item.productId)

      if (!product) {
        return res.status(404).json({
          success: false,
          message: `Product not found: ${item.productId}`,
        })
      }

      // WHY: Prevent negative stock values
      // HOW: Verify sufficient stock exists
      if (product.totalStock < item.quantity) {
        return res.status(400).json({
          success: false,
          message: `Not enough stock for product: ${product.title}`,
        })
      }

      product.totalStock -= item.quantity

      await product.save()
    }

    const getCartId = order.cartId
    await Cart.findByIdAndDelete(getCartId)

    await order.save()

    res.status(200).json({
      success: true,
      message: "Order confirmed",
      data: order,
    })
  } catch (e) {
    console.log(e)
    res.status(500).json({
      success: false,
      message: "Some error occured!",
    })
  }
}

const getAllOrdersByUser = async (req, res) => {
  try {
    const { userId } = req.params

    // WHY: Prevent users from viewing other users' order history (IDOR vulnerability)
    // HOW: Check if requested userId matches authenticated user
    if (req.user.id !== userId) {
      return res.status(403).json({
        success: false,
        message: "Unauthorized: Cannot access another user's orders",
      })
    }

    const orders = await Order.find({ userId })

    if (!orders.length) {
      return res.status(404).json({
        success: false,
        message: "No orders found!",
      })
    }

    res.status(200).json({
      success: true,
      data: orders,
    })
  } catch (e) {
    console.log(e)
    res.status(500).json({
      success: false,
      message: "Some error occured!",
    })
  }
}

const getOrderDetails = async (req, res) => {
  try {
    const { id } = req.params

    // WHY: Prevent invalid ID formats
    // HOW: Check ObjectId validity
    const mongoose = require("mongoose")
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid order ID format",
      })
    }

    const order = await Order.findById(id)

    if (!order) {
      return res.status(404).json({
        success: false,
        message: "Order not found!",
      })
    }

    // WHY: Prevent users from viewing other users' order details (IDOR vulnerability)
    // HOW: Check if order belongs to authenticated user or user is admin
    if (req.user.id !== order.userId.toString() && req.user.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Unauthorized: Cannot access this order",
      })
    }

    res.status(200).json({
      success: true,
      data: order,
    })
  } catch (e) {
    console.log(e)
    res.status(500).json({
      success: false,
      message: "Some error occured!",
    })
  }
}

module.exports = {
  createOrder,
  capturePayment,
  getAllOrdersByUser,
  getOrderDetails,
}
