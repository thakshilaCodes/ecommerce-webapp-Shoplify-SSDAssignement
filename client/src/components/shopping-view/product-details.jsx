import { StarIcon } from "lucide-react";
import { Avatar, AvatarFallback } from "../ui/avatar";
import { Button } from "../ui/button";
import { Dialog, DialogContent } from "../ui/dialog";
import { Separator } from "../ui/separator";
import { Input } from "../ui/input";
import { useDispatch, useSelector } from "react-redux";
import { addToCart, fetchCartItems } from "@/store/shop/cart-slice";
import { useToast } from "../ui/use-toast";
import { setProductDetails } from "@/store/shop/products-slice";
import { Label } from "../ui/label";
import StarRatingComponent from "../common/star-rating";
import { useEffect, useState } from "react";
import { addReview, getReviews } from "@/store/shop/review-slice";

// SECURITY: Input validation and sanitization functions
// WHY: Prevent XSS, injection attacks, and data corruption in reviews
// HOW: Validate and sanitize all user inputs before processing
const validateAndSanitizeReview = (reviewText, rating) => {
  const errors = [];
  
  // Validate rating
  if (rating < 1 || rating > 5 || !Number.isInteger(rating)) {
    errors.push("Rating must be a whole number between 1 and 5");
  }

  // Validate review message
  if (typeof reviewText !== 'string') {
    errors.push("Review must be text");
    return { isValid: false, errors, sanitized: "" };
  }

  const sanitized = reviewText.trim();
  
  // Check length
  if (sanitized.length < 1) {
    errors.push("Review cannot be empty");
  } else if (sanitized.length > 1000) {
    errors.push("Review must be less than 1000 characters");
  }

  // SECURITY: Prevent XSS and injection in reviews
  // WHY: User-generated content can contain malicious scripts
  // HOW: Remove or escape dangerous characters and patterns
  const dangerousPatterns = [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, // Script tags
    /javascript:/gi, // JavaScript protocol
    /on\w+\s*=/gi, // Event handlers
    /<\/?\w+[^>]*>/gi, // HTML tags
  ];

  let safeReview = sanitized;
  dangerousPatterns.forEach(pattern => {
    safeReview = safeReview.replace(pattern, '');
  });

  // Additional security: Escape special characters
  safeReview = safeReview
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');

  return {
    isValid: errors.length === 0,
    errors,
    sanitized: safeReview,
    rating: Math.max(1, Math.min(5, Math.round(rating))) // Ensure rating is between 1-5
  };
};

// SECURITY: Safe image URL validation
// WHY: Prevent malicious image URLs that could execute scripts
// HOW: Validate image URLs before rendering
const validateImageUrl = (url) => {
  if (!url || typeof url !== 'string') return false;
  
  try {
    const parsedUrl = new URL(url);
    // Allow only HTTP/HTTPS protocols for images
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      return false;
    }
    
    // Allow common image extensions
    const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg'];
    const hasValidExtension = allowedExtensions.some(ext => 
      parsedUrl.pathname.toLowerCase().endsWith(ext)
    );
    
    return hasValidExtension;
  } catch {
    // If URL parsing fails, it might be a data URL or relative path
    // Allow data URLs for base64 images but validate format
    if (url.startsWith('data:image/')) {
      const allowedDataTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
      return allowedDataTypes.some(type => url.startsWith(`data:${type}`));
    }
    
    // Allow relative paths
    if (url.startsWith('/') || url.startsWith('./') || url.startsWith('../')) {
      return true;
    }
    
    return false;
  }
};

function ProductDetailsDialog({ open, setOpen, productDetails }) {
  const [reviewMsg, setReviewMsg] = useState("");
  const [rating, setRating] = useState(0);
  const [validationErrors, setValidationErrors] = useState([]);
  const dispatch = useDispatch();
  const { user } = useSelector((state) => state.auth);
  const { cartItems } = useSelector((state) => state.shopCart);
  const { reviews } = useSelector((state) => state.shopReview);

  const { toast } = useToast();

  function handleRatingChange(getRating) {
    // SECURITY: Validate rating input
    // WHY: Prevent invalid rating values that could cause errors
    // HOW: Ensure rating is within valid range
    const safeRating = Math.max(0, Math.min(5, getRating));
    setRating(safeRating);
  }

  function handleAddToCart(getCurrentProductId, getTotalStock) {
    // SECURITY: Validate inputs before processing
    // WHY: Prevent invalid operations and potential errors
    // HOW: Check product ID and stock values
    if (!getCurrentProductId || !getTotalStock || getTotalStock < 0) {
      toast({
        title: "Invalid product information",
        variant: "destructive",
      });
      return;
    }

    // SECURITY: Validate user authentication
    // WHY: Prevent unauthorized cart operations
    // HOW: Check user object before proceeding
    if (!user?.id) {
      toast({
        title: "Please login to add items to cart",
        variant: "destructive",
      });
      return;
    }

    let getCartItems = cartItems?.items || [];

    if (getCartItems.length) {
      const indexOfCurrentItem = getCartItems.findIndex(
        (item) => item.productId === getCurrentProductId
      );
      if (indexOfCurrentItem > -1) {
        const getQuantity = getCartItems[indexOfCurrentItem].quantity;
        if (getQuantity + 1 > getTotalStock) {
          toast({
            title: `Only ${getTotalStock} items available in stock`,
            variant: "destructive",
          });
          return;
        }
      }
    }

    // SECURITY: Safe API call with error handling
    // WHY: Prevent unhandled promise rejections and provide user feedback
    // HOW: Proper error handling for dispatch operations
    dispatch(
      addToCart({
        userId: user.id,
        productId: getCurrentProductId,
        quantity: 1,
      })
    ).then((data) => {
      if (data?.payload?.success) {
        dispatch(fetchCartItems(user.id));
        toast({
          title: "Product added to cart",
        });
      } else {
        toast({
          title: "Failed to add product to cart",
          variant: "destructive",
        });
      }
    }).catch((error) => {
      console.error("Add to cart error:", error);
      toast({
        title: "Failed to add product to cart",
        variant: "destructive",
      });
    });
  }

  function handleDialogClose() {
    setOpen(false);
    dispatch(setProductDetails());
    setRating(0);
    setReviewMsg("");
    setValidationErrors([]);
  }

  function handleAddReview() {
    // SECURITY: Validate user authentication
    // WHY: Prevent unauthorized review submissions
    // HOW: Check user object before proceeding
    if (!user?.id) {
      toast({
        title: "Please login to add reviews",
        variant: "destructive",
      });
      return;
    }

    // SECURITY: Validate and sanitize review input
    // WHY: Prevent XSS and data corruption
    // HOW: Use validation function before processing
    const validation = validateAndSanitizeReview(reviewMsg, rating);
    
    if (!validation.isValid) {
      setValidationErrors(validation.errors);
      toast({
        title: "Invalid review data",
        description: validation.errors.join(", "),
        variant: "destructive",
      });
      return;
    }

    setValidationErrors([]);

    // SECURITY: Safe API call with validated data
    // WHY: Ensure only safe data is sent to backend
    // HOW: Use sanitized review text and validated rating
    dispatch(
      addReview({
        productId: productDetails?._id,
        userId: user.id,
        userName: user?.userName || "Anonymous",
        reviewMessage: validation.sanitized,
        reviewValue: validation.rating,
      })
    ).then((data) => {
      if (data?.payload?.success) {
        setRating(0);
        setReviewMsg("");
        dispatch(getReviews(productDetails?._id));
        toast({
          title: "Review added successfully!",
        });
      } else {
        toast({
          title: "Failed to add review",
          variant: "destructive",
        });
      }
    }).catch((error) => {
      console.error("Add review error:", error);
      toast({
        title: "Failed to add review",
        variant: "destructive",
      });
    });
  }

  useEffect(() => {
    // SECURITY: Validate product details before fetching reviews
    // WHY: Prevent unnecessary API calls with invalid data
    // HOW: Check if product exists and has valid ID
    if (productDetails?._id) {
      dispatch(getReviews(productDetails._id)).catch((error) => {
        console.error("Failed to fetch reviews:", error);
      });
    }
  }, [productDetails?._id]);

  // SECURITY: Safe calculation of average review
  // WHY: Prevent NaN errors and ensure valid calculations
  // HOW: Validate reviews array before processing
  const averageReview = (() => {
    if (!reviews || !Array.isArray(reviews) || reviews.length === 0) {
      return 0;
    }
    
    const validReviews = reviews.filter(review => 
      review && typeof review.reviewValue === 'number' && 
      review.reviewValue >= 1 && review.reviewValue <= 5
    );
    
    if (validReviews.length === 0) return 0;
    
    const sum = validReviews.reduce((sum, reviewItem) => sum + reviewItem.reviewValue, 0);
    return sum / validReviews.length;
  })();

  // SECURITY: Safe image URL
  // WHY: Prevent malicious image URLs
  // HOW: Validate image URL before rendering
  const safeImageUrl = validateImageUrl(productDetails?.image) 
    ? productDetails?.image 
    : '/images/placeholder-image.jpg';

  return (
    <Dialog open={open} onOpenChange={handleDialogClose}>
      <DialogContent className="grid grid-cols-1 lg:grid-cols-2 gap-8 sm:p-12 max-w-[90vw] sm:max-w-[80vw] lg:max-w-[70vw]">
        <div className="relative overflow-hidden rounded-lg">
          <img
            src={safeImageUrl}
            alt={productDetails?.title || "Product image"}
            width={600}
            height={600}
            className="aspect-square w-full object-cover"
            // SECURITY: Add loading attribute for performance and security
            // WHY: Prevent layout shifts and improve security
            loading="lazy"
            // SECURITY: Add referrer policy for privacy
            // WHY: Prevent sending referrer information to external domains
            referrerPolicy="no-referrer"
          />
        </div>
        <div className="">
          <div>
            <h1 className="text-3xl font-extrabold break-words">
              {productDetails?.title || "Product Title"}
            </h1>
            <p className="text-muted-foreground text-2xl mb-5 mt-4 break-words">
              {productDetails?.description || "Product description"}
            </p>
          </div>
          <div className="flex items-center justify-between">
            <p
              className={`text-3xl font-bold text-primary ${
                productDetails?.salePrice > 0 ? "line-through" : ""
              }`}
            >
              ${productDetails?.price || 0}
            </p>
            {productDetails?.salePrice > 0 ? (
              <p className="text-2xl font-bold text-muted-foreground">
                ${productDetails?.salePrice}
              </p>
            ) : null}
          </div>
          <div className="flex items-center gap-2 mt-2">
            <div className="flex items-center gap-0.5">
              <StarRatingComponent rating={averageReview} />
            </div>
            <span className="text-muted-foreground">
              ({averageReview.toFixed(2)})
            </span>
            <span className="text-muted-foreground text-sm">
              {reviews?.length || 0} reviews
            </span>
          </div>
          <div className="mt-5 mb-5">
            {productDetails?.totalStock === 0 ? (
              <Button className="w-full opacity-60 cursor-not-allowed">
                Out of Stock
              </Button>
            ) : (
              <Button
                className="w-full"
                onClick={() =>
                  handleAddToCart(
                    productDetails?._id,
                    productDetails?.totalStock
                  )
                }
              >
                Add to Cart
              </Button>
            )}
          </div>
          <Separator />
          <div className="max-h-[300px] overflow-auto">
            <h2 className="text-xl font-bold mb-4">Reviews</h2>
            <div className="grid gap-6">
              {reviews && reviews.length > 0 ? (
                reviews.map((reviewItem, index) => (
                  <div 
                    key={`review-${reviewItem?._id || index}`} 
                    className="flex gap-4"
                  >
                    <Avatar className="w-10 h-10 border">
                      <AvatarFallback>
                        {(reviewItem?.userName?.[0] || 'U').toUpperCase()}
                      </AvatarFallback>
                    </Avatar>
                    <div className="grid gap-1 flex-1">
                      <div className="flex items-center gap-2">
                        <h3 className="font-bold break-words">
                          {reviewItem?.userName || "Anonymous"}
                        </h3>
                      </div>
                      <div className="flex items-center gap-0.5">
                        <StarRatingComponent 
                          rating={reviewItem?.reviewValue || 0} 
                        />
                      </div>
                      <p className="text-muted-foreground break-words">
                        {/* SECURITY: Already sanitized content is safe to display */}
                        {reviewItem.reviewMessage}
                      </p>
                    </div>
                  </div>
                ))
              ) : (
                <h1 className="text-muted-foreground text-center py-4">
                  No Reviews Yet
                </h1>
              )}
            </div>
            <div className="mt-10 flex-col flex gap-2">
              <Label>Write a review</Label>
              
              {/* SECURITY: Display validation errors */}
              {validationErrors.length > 0 && (
                <div className="p-2 bg-destructive/10 border border-destructive rounded-md">
                  <ul className="text-sm text-destructive list-disc list-inside">
                    {validationErrors.map((error, index) => (
                      <li key={`error-${index}`}>{error}</li>
                    ))}
                  </ul>
                </div>
              )}
              
              <div className="flex gap-1">
                <StarRatingComponent
                  rating={rating}
                  handleRatingChange={handleRatingChange}
                />
              </div>
              <Input
                name="reviewMsg"
                value={reviewMsg}
                onChange={(event) => setReviewMsg(event.target.value)}
                placeholder="Write your review here..."
                // SECURITY: Limit input length
                // WHY: Prevent extremely long inputs that could cause issues
                maxLength={1000}
              />
              <div className="flex justify-between items-center">
                <span className="text-sm text-muted-foreground">
                  {reviewMsg.length}/1000 characters
                </span>
                <Button
                  onClick={handleAddReview}
                  disabled={reviewMsg.trim() === "" || rating === 0}
                >
                  Submit Review
                </Button>
              </div>
            </div>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export default ProductDetailsDialog;