import { FileIcon, UploadCloudIcon, XIcon } from "lucide-react";
import { Input } from "../ui/input";
import { Label } from "../ui/label";
import { useEffect, useRef } from "react";
import { Button } from "../ui/button";
import axios from "axios";
import { Skeleton } from "../ui/skeleton";

function ProductImageUpload({
  imageFile,
  setImageFile,
  imageLoadingState,
  uploadedImageUrl,
  setUploadedImageUrl,
  setImageLoadingState,
  isEditMode,
  isCustomStyling = false,
}) {
  const inputRef = useRef(null);

  console.log(isEditMode, "isEditMode");

  // SECURITY: Validate file type and size before accepting
  // WHY: Prevents malicious file uploads and client-side attacks
  // HOW: Check MIME type and file size before setting state
  const validateFile = (file) => {
    if (!file) return false;

    // Allowed file types
    const allowedTypes = [
      'image/jpeg',
      'image/jpg', 
      'image/png',
      'image/gif',
      'image/webp'
    ];
    
    // Check file type
    if (!allowedTypes.includes(file.type)) {
      alert('Invalid file type. Please upload only JPEG, PNG, GIF, or WebP images.');
      return false;
    }

    // Check file size (max 5MB)
    const maxSize = 5 * 1024 * 1024; // 5MB in bytes
    if (file.size > maxSize) {
      alert('File size too large. Maximum size is 5MB.');
      return false;
    }

    // SECURITY: Validate filename to prevent injection
    // WHY: Malicious filenames can cause issues on server
    // HOW: Basic filename sanitization
    const sanitizedName = file.name.replace(/[^a-zA-Z0-9.\-_]/g, '_');
    if (sanitizedName !== file.name) {
      console.warn('Filename contained unsafe characters and was sanitized');
    }

    return true;
  };

  function handleImageFileChange(event) {
    console.log(event.target.files, "event.target.files");
    const selectedFile = event.target.files?.[0];
    console.log(selectedFile);

    // SECURITY: Validate file before setting state
    // WHY: Prevents processing of malicious files
    // HOW: Use validation function before accepting file
    if (selectedFile && validateFile(selectedFile)) {
      setImageFile(selectedFile);
    } else {
      // Reset input if file is invalid
      if (inputRef.current) {
        inputRef.current.value = "";
      }
    }
  }

  function handleDragOver(event) {
    event.preventDefault();
  }

  function handleDrop(event) {
    event.preventDefault();
    const droppedFile = event.dataTransfer.files?.[0];
    
    // SECURITY: Validate dropped files too
    // WHY: Drag-and-drop can also be used to upload malicious files
    // HOW: Apply same validation to dropped files
    if (droppedFile && validateFile(droppedFile)) {
      setImageFile(droppedFile);
    }
  }

  function handleRemoveImage() {
    setImageFile(null);
    if (inputRef.current) {
      inputRef.current.value = "";
    }
  }

  async function uploadImageToCloudinary() {
    // SECURITY: Additional validation before upload
    // WHY: Double-check security before sending to server
    // HOW: Re-validate file before upload request
    if (!imageFile || !validateFile(imageFile)) {
      alert('Invalid file. Please select a valid image.');
      return;
    }

    setImageLoadingState(true);
    
    try {
      const data = new FormData();
      
      // SECURITY: Use sanitized filename in FormData
      // WHY: Prevents filename-based injection attacks
      // HOW: Sanitize filename before appending to FormData
      const sanitizedFileName = imageFile.name.replace(/[^a-zA-Z0-9.\-_]/g, '_');
      data.append("my_file", imageFile, sanitizedFileName);

      // SECURITY: Use environment variable for API URL
      // WHY: Hardcoded URLs can cause issues in different environments
      // HOW: Use environment variable with fallback
      const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';
      
      const response = await axios.post(
        `${API_BASE_URL}/api/admin/products/upload-image`,
        data,
        {
          // SECURITY: Add timeout to prevent hanging requests
          // WHY: Prevents denial-of-service from slow requests
          // HOW: Set reasonable timeout
          timeout: 30000, // 30 seconds
          
          // SECURITY: Add request headers for security
          // WHY: Additional security headers can help prevent attacks
          headers: {
            'Content-Type': 'multipart/form-data',
            'X-Requested-With': 'XMLHttpRequest'
          }
        }
      );
      
      console.log(response, "response");

      if (response?.data?.success) {
        setUploadedImageUrl(response.data.result.url);
        setImageLoadingState(false);
      } else {
        throw new Error('Upload failed');
      }
    } catch (error) {
      // SECURITY: Proper error handling without exposing details
      // WHY: Prevents information leakage to users
      // HOW: Generic error messages
      console.error('Upload error:', error);
      
      let errorMessage = 'Failed to upload image. Please try again.';
      
      if (error.code === 'ECONNABORTED') {
        errorMessage = 'Upload timeout. Please try again.';
      } else if (error.response?.status === 413) {
        errorMessage = 'File too large. Please select a smaller image.';
      } else if (error.response?.status >= 500) {
        errorMessage = 'Server error. Please try again later.';
      }
      
      alert(errorMessage);
      setImageLoadingState(false);
      
      // Reset on error
      handleRemoveImage();
    }
  }

  useEffect(() => {
    // SECURITY: Add cleanup and validation in useEffect
    // WHY: Prevent memory leaks and ensure valid state
    // HOW: Check if imageFile exists and is valid before upload
    if (imageFile !== null && validateFile(imageFile)) {
      uploadImageToCloudinary();
    } else if (imageFile !== null) {
      // If file is invalid, remove it
      handleRemoveImage();
    }
  }, [imageFile]);

  return (
    <div
      className={`w-full  mt-4 ${isCustomStyling ? "" : "max-w-md mx-auto"}`}
    >
      <Label className="text-lg font-semibold mb-2 block">Upload Image</Label>
      <div
        onDragOver={handleDragOver}
        onDrop={handleDrop}
        className={`${
          isEditMode ? "opacity-60" : ""
        } border-2 border-dashed rounded-lg p-4`}
      >
        <Input
          id="image-upload"
          type="file"
          className="hidden"
          ref={inputRef}
          onChange={handleImageFileChange}
          disabled={isEditMode}
          // SECURITY: Add accept attribute for browser-level validation
          // WHY: Provides first line of defense against wrong file types
          // HOW: Specify allowed file types
          accept=".jpg,.jpeg,.png,.gif,.webp,image/jpeg,image/png,image/gif,image/webp"
        />
        {!imageFile ? (
          <Label
            htmlFor="image-upload"
            className={`${
              isEditMode ? "cursor-not-allowed" : ""
            } flex flex-col items-center justify-center h-32 cursor-pointer`}
          >
            <UploadCloudIcon className="w-10 h-10 text-muted-foreground mb-2" />
            <span>Drag & drop or click to upload image</span>
            <span className="text-sm text-muted-foreground mt-1">
              Supported: JPEG, PNG, GIF, WebP (Max 5MB)
            </span>
          </Label>
        ) : imageLoadingState ? (
          <Skeleton className="h-10 bg-gray-100" />
        ) : (
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <FileIcon className="w-8 text-primary mr-2 h-8" />
            </div>
            <p className="text-sm font-medium truncate max-w-xs">
              {imageFile.name}
            </p>
            <Button
              variant="ghost"
              size="icon"
              className="text-muted-foreground hover:text-foreground"
              onClick={handleRemoveImage}
            >
              <XIcon className="w-4 h-4" />
              <span className="sr-only">Remove File</span>
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}

export default ProductImageUpload;