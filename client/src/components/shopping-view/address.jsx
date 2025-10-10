import { useEffect, useState } from "react";
import CommonForm from "../common/form";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { addressFormControls } from "@/config";
import { useDispatch, useSelector } from "react-redux";
import {
  addNewAddress,
  deleteAddress,
  editaAddress,
  fetchAllAddresses,
} from "@/store/shop/address-slice";
import AddressCard from "./address-card";
import { useToast } from "../ui/use-toast";

const initialAddressFormData = {
  address: "",
  city: "",
  phone: "",
  pincode: "",
  notes: "",
};

// SECURITY: Input validation and sanitization functions
// WHY: Prevent XSS, injection attacks, and data corruption
// HOW: Validate and sanitize all user inputs before processing
const validateAndSanitizeAddressInput = (input) => {
  const errors = [];
  const sanitized = { ...input };

  // Validate and sanitize address
  if (typeof input.address === 'string') {
    sanitized.address = input.address.trim();
    if (sanitized.address.length < 5 || sanitized.address.length > 200) {
      errors.push("Address must be between 5 and 200 characters");
    } else if (!/^[a-zA-Z0-9\s,.\-#/]+$/.test(sanitized.address)) {
      errors.push("Address contains invalid characters");
    }
  }

  // Validate and sanitize city
  if (typeof input.city === 'string') {
    sanitized.city = input.city.trim();
    if (sanitized.city.length < 2 || sanitized.city.length > 50) {
      errors.push("City must be between 2 and 50 characters");
    } else if (!/^[a-zA-Z\s-]+$/.test(sanitized.city)) {
      errors.push("City contains invalid characters");
    }
  }

  // Validate and sanitize pincode
  if (typeof input.pincode === 'string') {
    sanitized.pincode = input.pincode.trim();
    if (!/^[0-9\s-]{4,10}$/.test(sanitized.pincode)) {
      errors.push("Invalid pincode format");
    }
  }

  // Validate and sanitize phone
  if (typeof input.phone === 'string') {
    sanitized.phone = input.phone.trim();
    if (!/^[+]?[(]?[0-9]{1,4}[)]?[\s-]?[(]?[0-9]{1,4}[)]?[\s-]?[0-9]{3,4}[\s-]?[0-9]{3,4}$/.test(sanitized.phone)) {
      errors.push("Invalid phone number format");
    }
  }

  // Validate and sanitize notes (optional)
  if (typeof input.notes === 'string') {
    sanitized.notes = input.notes.trim();
    if (sanitized.notes.length > 500) {
      errors.push("Notes must not exceed 500 characters");
    } else if (sanitized.notes && !/^[a-zA-Z0-9\s,.\-!?()]+$/.test(sanitized.notes)) {
      errors.push("Notes contain invalid characters");
    }
  }

  return {
    isValid: errors.length === 0,
    errors,
    sanitized
  };
};

function Address({ setCurrentSelectedAddress, selectedId }) {
  const [formData, setFormData] = useState(initialAddressFormData);
  const [currentEditedId, setCurrentEditedId] = useState(null);
  const [validationErrors, setValidationErrors] = useState([]);
  const dispatch = useDispatch();
  const { user } = useSelector((state) => state.auth);
  const { addressList } = useSelector((state) => state.shopAddress);
  const { toast } = useToast();

  // SECURITY: Validate user object exists and has required properties
  // WHY: Prevent errors and ensure secure operations
  // HOW: Check user object before using its properties
  const getUserId = () => {
    if (!user || !user.id) {
      console.error("User not authenticated");
      toast({
        title: "Authentication error",
        variant: "destructive",
      });
      throw new Error("User not authenticated");
    }
    return user.id;
  };

  function handleManageAddress(event) {
    event.preventDefault();

    // SECURITY: Validate all inputs before processing
    // WHY: Prevent injection attacks and data corruption
    // HOW: Use validation function before dispatching actions
    const validation = validateAndSanitizeAddressInput(formData);
    
    if (!validation.isValid) {
      setValidationErrors(validation.errors);
      toast({
        title: "Invalid input data",
        description: validation.errors.join(", "),
        variant: "destructive",
      });
      return;
    }

    setValidationErrors([]);

    try {
      const userId = getUserId();

      // SECURITY: Limit number of addresses per user
      // WHY: Prevent resource exhaustion and abuse
      // HOW: Enforce reasonable limits
      if (addressList.length >= 5 && currentEditedId === null) {
        setFormData(initialAddressFormData);
        toast({
          title: "Maximum limit reached",
          description: "You can add up to 5 addresses",
          variant: "destructive",
        });
        return;
      }

      // SECURITY: Use sanitized data for API calls
      // WHY: Prevent NoSQL injection and XSS attacks
      // HOW: Pass validated and sanitized data to backend
      if (currentEditedId !== null) {
        dispatch(
          editaAddress({
            userId: userId,
            addressId: currentEditedId,
            formData: validation.sanitized, // Use sanitized data
          })
        ).then((data) => {
          if (data?.payload?.success) {
            dispatch(fetchAllAddresses(userId));
            setCurrentEditedId(null);
            setFormData(initialAddressFormData);
            setValidationErrors([]);
            toast({
              title: "Address updated successfully",
            });
          } else {
            // SECURITY: Handle API errors securely
            // WHY: Prevent information disclosure
            // HOW: Generic error messages
            toast({
              title: "Failed to update address",
              variant: "destructive",
            });
          }
        }).catch((error) => {
          console.error("Edit address error:", error);
          toast({
            title: "Failed to update address",
            variant: "destructive",
          });
        });
      } else {
        dispatch(
          addNewAddress({
            ...validation.sanitized, // Use sanitized data
            userId: userId,
          })
        ).then((data) => {
          if (data?.payload?.success) {
            dispatch(fetchAllAddresses(userId));
            setFormData(initialAddressFormData);
            setValidationErrors([]);
            toast({
              title: "Address added successfully",
            });
          } else {
            toast({
              title: "Failed to add address",
              variant: "destructive",
            });
          }
        }).catch((error) => {
          console.error("Add address error:", error);
          toast({
            title: "Failed to add address",
            variant: "destructive",
          });
        });
      }
    } catch (error) {
      console.error("Address management error:", error);
      toast({
        title: "Operation failed",
        variant: "destructive",
      });
    }
  }

  function handleDeleteAddress(getCurrentAddress) {
    // SECURITY: Validate address object before deletion
    // WHY: Prevent deletion of invalid or unauthorized addresses
    // HOW: Check address object structure
    if (!getCurrentAddress || !getCurrentAddress._id) {
      toast({
        title: "Invalid address",
        variant: "destructive",
      });
      return;
    }

    try {
      const userId = getUserId();
      
      dispatch(
        deleteAddress({ 
          userId: userId, 
          addressId: getCurrentAddress._id 
        })
      ).then((data) => {
        if (data?.payload?.success) {
          dispatch(fetchAllAddresses(userId));
          toast({
            title: "Address deleted successfully",
          });
        } else {
          toast({
            title: "Failed to delete address",
            variant: "destructive",
          });
        }
      }).catch((error) => {
        console.error("Delete address error:", error);
        toast({
          title: "Failed to delete address",
          variant: "destructive",
        });
      });
    } catch (error) {
      console.error("Delete operation error:", error);
      toast({
        title: "Operation failed",
        variant: "destructive",
      });
    }
  }

  function handleEditAddress(getCurrentAddress) {
    // SECURITY: Validate address object before editing
    // WHY: Prevent editing of invalid or unauthorized addresses
    // HOW: Check address object structure
    if (!getCurrentAddress || !getCurrentAddress._id) {
      toast({
        title: "Invalid address",
        variant: "destructive",
      });
      return;
    }

    setCurrentEditedId(getCurrentAddress._id);
    
    // SECURITY: Use safe data assignment
    // WHY: Prevent prototype pollution and unexpected data
    // HOW: Explicitly assign only expected fields
    setFormData({
      address: getCurrentAddress?.address || "",
      city: getCurrentAddress?.city || "",
      phone: getCurrentAddress?.phone || "",
      pincode: getCurrentAddress?.pincode || "",
      notes: getCurrentAddress?.notes || "",
    });
    setValidationErrors([]);
  }

  function isFormValid() {
    // SECURITY: Enhanced form validation
    // WHY: Ensure all required fields are properly filled
    // HOW: Check for empty strings and validate content
    const requiredFields = ['address', 'city', 'phone', 'pincode'];
    const hasRequiredFields = requiredFields.every(
      field => formData[field] && formData[field].trim() !== ""
    );
    
    if (!hasRequiredFields) return false;
    
    // Additional validation check
    const validation = validateAndSanitizeAddressInput(formData);
    return validation.isValid;
  }

  useEffect(() => {
    // SECURITY: Validate user before fetching addresses
    // WHY: Prevent unauthorized API calls
    // HOW: Check authentication state
    if (user?.id) {
      dispatch(fetchAllAddresses(user.id)).catch((error) => {
        console.error("Failed to fetch addresses:", error);
        toast({
          title: "Failed to load addresses",
          variant: "destructive",
        });
      });
    }
  }, [dispatch, user?.id]);

  // SECURITY: Safe console log for debugging
  // WHY: Prevent logging sensitive information in production
  // HOW: Conditional logging
  if (process.env.NODE_ENV === 'development') {
    console.log("Address list loaded:", addressList?.length || 0);
  }

  return (
    <Card>
      <div className="mb-5 p-3 grid grid-cols-1 sm:grid-cols-2 gap-2">
        {addressList && addressList.length > 0
          ? addressList.map((singleAddressItem, index) => (
              <AddressCard
                key={`address-${singleAddressItem._id || index}`} // SECURITY: Proper keys for list rendering
                selectedId={selectedId}
                handleDeleteAddress={handleDeleteAddress}
                addressInfo={singleAddressItem}
                handleEditAddress={handleEditAddress}
                setCurrentSelectedAddress={setCurrentSelectedAddress}
              />
            ))
          : null}
      </div>
      <CardHeader>
        <CardTitle>
          {currentEditedId !== null ? "Edit Address" : "Add New Address"}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {/* SECURITY: Display validation errors to user */}
        {/* WHY: Help users understand input requirements */}
        {/* HOW: Show validation errors clearly */}
        {validationErrors.length > 0 && (
          <div className="p-3 bg-destructive/10 border border-destructive rounded-md">
            <h4 className="text-sm font-medium text-destructive mb-1">
              Please fix the following errors:
            </h4>
            <ul className="text-sm text-destructive list-disc list-inside">
              {validationErrors.map((error, index) => (
                <li key={`error-${index}`}>{error}</li>
              ))}
            </ul>
          </div>
        )}
        
        <CommonForm
          formControls={addressFormControls}
          formData={formData}
          setFormData={setFormData}
          buttonText={currentEditedId !== null ? "Update Address" : "Add Address"}
          onSubmit={handleManageAddress}
          isBtnDisabled={!isFormValid()}
        />
      </CardContent>
    </Card>
  );
}

export default Address;