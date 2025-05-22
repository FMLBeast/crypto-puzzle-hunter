"""
Module for extracting hidden data from images using steganography techniques.
"""
from PIL import Image
import numpy as np
import io
from typing import Dict, List, Tuple, Union, Optional
import os

def analyze_steganography(file_path=None, image_data=None, bit_planes=None, regions=None):
    """
    Analyze an image for steganographic content.
    
    Args:
        file_path: Path to the image file (optional if image_data provided)
        image_data: Raw image data bytes (optional if file_path provided)
        bit_planes: List of bit planes to analyze (default: [0, 1, 6, 7])
        regions: List of regions to analyze (default: ["full", "top", "bottom"])
        
    Returns:
        Dictionary with analysis results
    """
    # Validate input
    if not file_path and not image_data:
        return {"error": "Either file_path or image_data must be provided"}
    
    # Default parameters if not provided
    if bit_planes is None:
        bit_planes = [0, 1, 6, 7]  # Common bit planes for steganography
        
    if regions is None:
        regions = ["full", "top", "bottom", "left", "right"]
    
    # Read file if path is provided
    if file_path and not image_data:
        try:
            with open(file_path, 'rb') as f:
                image_data = f.read()
        except Exception as e:
            return {"error": f"Failed to read image file: {str(e)}"}
    
    try:
        # Open the image
        img = Image.open(io.BytesIO(image_data))
        
        # Convert to RGB if not already
        if img.mode != 'RGB':
            img = img.convert('RGB')
            
        width, height = img.size
        
        # Create array from image
        img_array = np.array(img)
        
        results = {
            "file_size": len(image_data),
            "dimensions": f"{width}x{height}",
            "extractions": [],
            "summary": {}
        }
        
        # Analyze each bit plane
        for bit_plane in bit_planes:
            # Process each region
            for region_name in regions:
                region_array = extract_region(img_array, region_name)
                
                # Extract LSB data from this region and bit plane
                binary_data = extract_lsb_data(region_array, bit_plane)
                
                # Check if there's a pattern in the data
                has_pattern, pattern_type = check_binary_pattern(binary_data)
                
                # Add to results if pattern found
                if has_pattern:
                    results["extractions"].append({
                        "bit_plane": bit_plane,
                        "region": region_name,
                        "pattern_type": pattern_type,
                        "binary_data": binary_data[:1000] + "..." if len(binary_data) > 1000 else binary_data
                    })
        
        # Determine if steganography is likely present
        if results["extractions"]:
            # If we found patterns in the extractions, steganography is likely
            results["conclusion"] = {
                "steganography_likelihood": "High" if len(results["extractions"]) > 3 else "Medium",
                "evidence": [f"Pattern found in bit plane {ext['bit_plane']}, region {ext['region']}"
                             for ext in results["extractions"][:3]]
            }
        else:
            results["conclusion"] = {
                "steganography_likelihood": "Low",
                "evidence": ["No significant patterns found in analyzed bit planes and regions"]
            }
            
        return results
    
    except Exception as e:
        return {"error": f"Steganography analysis failed: {str(e)}"}

def extract_region(img_array, region_name):
    """
    Extract a region from an image array.
    
    Args:
        img_array: Numpy array of the image
        region_name: Name of the region to extract
        
    Returns:
        Numpy array of the extracted region
    """
    height, width, _ = img_array.shape
    
    if region_name == "full":
        return img_array
    elif region_name == "top":
        return img_array[:height//2, :, :]
    elif region_name == "bottom":
        return img_array[height//2:, :, :]
    elif region_name == "left":
        return img_array[:, :width//2, :]
    elif region_name == "right":
        return img_array[:, width//2:, :]
    elif region_name == "top_left":
        return img_array[:height//2, :width//2, :]
    elif region_name == "top_right":
        return img_array[:height//2, width//2:, :]
    elif region_name == "bottom_left":
        return img_array[height//2:, :width//2, :]
    elif region_name == "bottom_right":
        return img_array[height//2:, width//2:, :]
    else:
        # Default to full image
        return img_array

def extract_lsb_data(img_array, bit_plane=0):
    """
    Extract LSB data from an image array.
    
    Args:
        img_array: Numpy array of the image
        bit_plane: Bit plane to extract (0 = LSB, 1 = second LSB, etc.)
        
    Returns:
        Binary string of extracted data
    """
    # Create bit mask for the specified bit plane
    mask = 1 << bit_plane
    
    # Initialize binary string
    binary_data = ""
    
    # Extract the bits from each channel of each pixel
    height, width, channels = img_array.shape
    
    # Limit to first 10000 pixels to avoid excessive data
    max_pixels = min(10000, height * width)
    pixels_processed = 0
    
    for y in range(height):
        if pixels_processed >= max_pixels:
            break
            
        for x in range(width):
            if pixels_processed >= max_pixels:
                break
                
            pixel = img_array[y, x]
            for channel in range(channels):
                # Extract the bit at the specified bit plane
                bit = (pixel[channel] & mask) >> bit_plane
                binary_data += str(bit)
            
            pixels_processed += 1
    
    return binary_data

def check_binary_pattern(binary_data):
    """
    Check for patterns in binary data that might indicate steganography.
    
    Args:
        binary_data: Binary string to analyze
        
    Returns:
        Tuple of (has_pattern, pattern_type)
    """
    # Ensure we have enough data to analyze
    if len(binary_data) < 100:
        return False, None
    
    # Check distribution of 0s and 1s
    ones_count = binary_data.count('1')
    zeros_count = binary_data.count('0')
    total_count = ones_count + zeros_count
    
    # Calculate distribution ratio
    distribution_ratio = min(ones_count, zeros_count) / max(ones_count, zeros_count)
    
    # Check for repeating patterns
    has_repeating_pattern = False
    pattern_length = 0
    
    # Check for patterns of length 2-16
    for length in range(2, 17):
        if len(binary_data) >= length * 3:  # Need enough data to check for repeats
            for i in range(len(binary_data) - length * 2):
                pattern = binary_data[i:i+length]
                if pattern == binary_data[i+length:i+length*2]:
                    has_repeating_pattern = True
                    pattern_length = length
                    break
            
            if has_repeating_pattern:
                break
    
    # Determine if there's a pattern
    if distribution_ratio < 0.3:  # Very skewed distribution
        return True, "skewed_distribution"
    elif has_repeating_pattern:
        return True, f"repeating_pattern_{pattern_length}"
    else:
        # Check for alternating patterns
        alternating = True
        for i in range(2, min(100, len(binary_data))):
            if binary_data[i] != binary_data[i % 2]:
                alternating = False
                break
        
        if alternating:
            return True, "alternating_pattern"
    
    # No significant pattern found
    return False, None
