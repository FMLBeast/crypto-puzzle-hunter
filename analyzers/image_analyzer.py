"""
Image analyzer module for Crypto Hunter

This module provides functions for analyzing images and detecting
steganography or hidden data within them.
"""
import logging
import io
import re
import math
import binascii
from typing import Dict, List, Any, Optional, Tuple, Union
from pathlib import Path

from core.state import State
from analyzers.base import register_analyzer, analyzer_compatibility

logger = logging.getLogger(__name__)

# Try to import PIL for image processing
try:
    from PIL import Image, ExifTags, ImageChops, ImageStat
    PIL_AVAILABLE = True
except ImportError:
    logger.warning("PIL not available, image analysis will be limited")
    PIL_AVAILABLE = False

# Try to import numpy for advanced image analysis
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    logger.warning("NumPy not available, advanced image analysis will be limited")
    NUMPY_AVAILABLE = False


@register_analyzer("image_analyze")
@analyzer_compatibility(file_types=["png", "jpg", "jpeg", "gif", "bmp", "tiff"], requires_binary=True)
def analyze_image(state: State) -> State:
    """
    Main image analyzer function that orchestrates image analysis.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_data:
        state.add_insight("No image data available for analysis", analyzer="image_analyzer")
        return state
    
    # Check if PIL is available
    if not PIL_AVAILABLE:
        state.add_insight("PIL not available, image analysis will be limited", analyzer="image_analyzer")
        return state
    
    # Run various image analysis functions
    state = extract_metadata(state)
    state = analyze_image_properties(state)
    state = detect_steganography(state)
    state = analyze_color_channels(state)
    state = check_pixel_patterns(state)
    
    return state


@register_analyzer("extract_metadata")
@analyzer_compatibility(file_types=["png", "jpg", "jpeg", "gif", "bmp", "tiff"], requires_binary=True)
def extract_metadata(state: State) -> State:
    """
    Extract metadata from image files.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_data or not PIL_AVAILABLE:
        return state
    
    try:
        # Load image from binary data
        img_data = io.BytesIO(state.puzzle_data)
        img = Image.open(img_data)
        
        # Extract basic properties
        properties = {
            "format": img.format,
            "size": img.size,
            "mode": img.mode,
            "info": img.info
        }
        
        state.add_insight(
            f"Image properties: {img.format}, {img.size[0]}x{img.size[1]}px, mode={img.mode}",
            analyzer="image_analyzer",
            data=properties
        )
        
        # Extract EXIF data if present
        if hasattr(img, '_getexif') and img._getexif():
            exif = {
                ExifTags.TAGS.get(tag, tag): value
                for tag, value in img._getexif().items()
                if tag in ExifTags.TAGS
            }
            
            # Clean up binary data in EXIF
            clean_exif = {}
            for key, value in exif.items():
                if isinstance(value, bytes):
                    # Check if it might contain text
                    try:
                        text_value = value.decode('utf-8', errors='replace')
                        if any(c.isalnum() for c in text_value):
                            clean_exif[key] = text_value
                        else:
                            clean_exif[key] = f"Binary data ({len(value)} bytes)"
                    except:
                        clean_exif[key] = f"Binary data ({len(value)} bytes)"
                else:
                    clean_exif[key] = value
            
            # Add insight with EXIF data
            state.add_insight(
                f"EXIF data found with {len(clean_exif)} entries",
                analyzer="image_analyzer",
                data={"exif": clean_exif}
            )
            
            # Look for interesting EXIF data
            interesting_keys = [
                "Artist", "Copyright", "ImageDescription", "UserComment",
                "Software", "Author", "Comment", "Title", "Subject"
            ]
            
            for key in interesting_keys:
                if key in clean_exif:
                    state.add_insight(
                        f"Interesting EXIF data found: {key} = {clean_exif[key]}",
                        analyzer="image_analyzer"
                    )
        
        # Check for PNG text chunks
        if img.format == 'PNG' and img.info:
            text_chunks = {k: v for k, v in img.info.items() if isinstance(k, str) and isinstance(v, str)}
            if text_chunks:
                state.add_insight(
                    f"PNG text chunks found: {text_chunks}",
                    analyzer="image_analyzer",
                    data={"text_chunks": text_chunks}
                )
        
        # Check for comments in image
        if img.format == 'JPEG' and 'comment' in img.info:
            comment = img.info['comment']
            if isinstance(comment, bytes):
                comment = comment.decode('utf-8', errors='replace')
            
            state.add_insight(
                f"JPEG comment found: {comment}",
                analyzer="image_analyzer",
                data={"comment": comment}
            )
    
    except Exception as e:
        state.add_insight(f"Error extracting image metadata: {e}", analyzer="image_analyzer")
    
    return state


@register_analyzer("analyze_image_properties")
@analyzer_compatibility(file_types=["png", "jpg", "jpeg", "gif", "bmp", "tiff"], requires_binary=True)
def analyze_image_properties(state: State) -> State:
    """
    Analyze basic image properties for anomalies.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_data or not PIL_AVAILABLE:
        return state
    
    try:
        # Load image
        img_data = io.BytesIO(state.puzzle_data)
        img = Image.open(img_data)
        
        # Check for unusual image dimensions
        width, height = img.size
        
        if width % 8 == 0 and height % 8 == 0:
            state.add_insight(
                f"Image dimensions ({width}x{height}) are multiples of 8, common for steganography",
                analyzer="image_analyzer"
            )
        
        if width == height:
            state.add_insight(
                f"Image is a perfect square ({width}x{height})",
                analyzer="image_analyzer"
            )
        
        # Check for unusual bit depth
        bit_depth = None
        if img.mode == '1':
            bit_depth = 1
        elif img.mode == 'L':
            bit_depth = 8
        elif img.mode == 'RGB':
            bit_depth = 24
        elif img.mode == 'RGBA':
            bit_depth = 32
        
        if bit_depth:
            state.add_insight(
                f"Image bit depth: {bit_depth}",
                analyzer="image_analyzer",
                data={"bit_depth": bit_depth}
            )
            
            if bit_depth == 1:
                state.add_insight(
                    "1-bit image detected - common for QR codes or binary puzzles",
                    analyzer="image_analyzer"
                )
        
        # Check for palette
        if img.mode == 'P':
            state.add_insight(
                "Image uses palette mode, could contain hidden data in palette",
                analyzer="image_analyzer"
            )
            
            # Extract palette
            if hasattr(img, 'palette') and img.palette:
                palette_data = img.getpalette()
                palette_size = len(palette_data) // 3
                state.add_insight(
                    f"Image has a palette with {palette_size} colors",
                    analyzer="image_analyzer",
                    data={"palette_size": palette_size}
                )
                
                # Check for unusual palette usage
                if palette_size > 100:  # Typically, palettes are 256 colors or fewer
                    state.add_insight(
                        f"Large palette detected ({palette_size} colors), might contain hidden data",
                        analyzer="image_analyzer"
                    )
        
        # Check for alpha channel
        if 'A' in img.mode:
            state.add_insight(
                "Image has alpha channel, might contain hidden data",
                analyzer="image_analyzer"
            )
            
            # Extract alpha channel
            if NUMPY_AVAILABLE:
                try:
                    img_array = np.array(img)
                    alpha_channel = img_array[:, :, 3] if img_array.ndim == 3 and img_array.shape[2] >= 4 else None
                    
                    if alpha_channel is not None:
                        # Check for unusual patterns in alpha
                        unique_alpha = np.unique(alpha_channel)
                        if len(unique_alpha) > 1 and len(unique_alpha) < 10:
                            state.add_insight(
                                f"Alpha channel has unusual pattern with {len(unique_alpha)} unique values",
                                analyzer="image_analyzer",
                                data={"unique_alpha_values": unique_alpha.tolist()}
                            )
                            
                            # Extract alpha as separate image
                            alpha_img = Image.fromarray(alpha_channel)
                            alpha_buffer = io.BytesIO()
                            alpha_img.save(alpha_buffer, format="PNG")
                            
                            state.add_transformation(
                                name="extract_alpha_channel",
                                description="Extracted alpha channel as separate image",
                                input_data=state.puzzle_data,
                                output_data=alpha_buffer.getvalue(),
                                analyzer="image_analyzer"
                            )
                except Exception as e:
                    logger.debug(f"Error analyzing alpha channel: {e}")
    
    except Exception as e:
        state.add_insight(f"Error analyzing image properties: {e}", analyzer="image_analyzer")
    
    return state


@register_analyzer("detect_steganography")
@analyzer_compatibility(file_types=["png", "jpg", "jpeg", "gif", "bmp", "tiff"], requires_binary=True)
def detect_steganography(state: State) -> State:
    """
    Detect potential steganography in images.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_data or not PIL_AVAILABLE:
        return state
    
    try:
        # Load image
        img_data = io.BytesIO(state.puzzle_data)
        img = Image.open(img_data)
        
        # Check for LSB steganography
        if img.mode in ('RGB', 'RGBA', 'L'):
            lsb_result = check_lsb_steganography(img)
            
            if lsb_result['potential_steganography']:
                state.add_insight(
                    f"Potential LSB steganography detected ({lsb_result['score']:.2f}/10)",
                    analyzer="image_analyzer",
                    data=lsb_result
                )
                
                if lsb_result['score'] > 7:
                    # Try to extract LSB data
                    try:
                        extracted_data = extract_lsb_data(img)
                        
                        # Check if extracted data might be text
                        potential_text = is_potential_text(extracted_data)
                        
                        if potential_text:
                            state.add_transformation(
                                name="extract_lsb_text",
                                description="Extracted potential text from LSB",
                                input_data=state.puzzle_data,
                                output_data=extracted_data.decode('utf-8', errors='replace'),
                                analyzer="image_analyzer"
                            )
                        else:
                            state.add_transformation(
                                name="extract_lsb_binary",
                                description="Extracted binary data from LSB",
                                input_data=state.puzzle_data,
                                output_data=extracted_data,
                                analyzer="image_analyzer"
                            )
                    except Exception as e:
                        logger.debug(f"Error extracting LSB data: {e}")
        
        # Check for visible watermarks or patterns
        watermark_result = check_for_watermark(img)
        if watermark_result['potential_watermark']:
            state.add_insight(
                "Potential visible watermark or pattern detected",
                analyzer="image_analyzer",
                data=watermark_result
            )
            
            # Extract enhanced watermark if found
            if 'enhanced_watermark' in watermark_result:
                enhanced_img = watermark_result['enhanced_watermark']
                enhanced_buffer = io.BytesIO()
                enhanced_img.save(enhanced_buffer, format="PNG")
                
                state.add_transformation(
                    name="enhance_watermark",
                    description="Enhanced potential watermark",
                    input_data=state.puzzle_data,
                    output_data=enhanced_buffer.getvalue(),
                    analyzer="image_analyzer"
                )
        
        # Check for data in image file after image data
        if state.puzzle_data:
            try:
                # Get the actual image data size
                img_data = io.BytesIO(state.puzzle_data)
                img = Image.open(img_data)
                
                # Save the image to a new buffer to compare sizes
                clean_buffer = io.BytesIO()
                img.save(clean_buffer, format=img.format)
                
                clean_size = clean_buffer.tell()
                original_size = len(state.puzzle_data)
                
                if original_size > clean_size + 16:  # Allow for small differences
                    excess_data = state.puzzle_data[clean_size:]
                    
                    state.add_insight(
                        f"Found {len(excess_data)} bytes of extra data after image content",
                        analyzer="image_analyzer",
                        data={"excess_size": len(excess_data)}
                    )
                    
                    # Check if the excess data might be a message
                    if is_potential_text(excess_data):
                        state.add_transformation(
                            name="extract_excess_text",
                            description="Extracted text from data after image",
                            input_data=state.puzzle_data,
                            output_data=excess_data.decode('utf-8', errors='replace'),
                            analyzer="image_analyzer"
                        )
                    else:
                        state.add_transformation(
                            name="extract_excess_binary",
                            description="Extracted binary data from after image",
                            input_data=state.puzzle_data,
                            output_data=excess_data,
                            analyzer="image_analyzer"
                        )
            except Exception as e:
                logger.debug(f"Error checking for data after image: {e}")
    
    except Exception as e:
        state.add_insight(f"Error detecting steganography: {e}", analyzer="image_analyzer")
    
    return state


@register_analyzer("analyze_color_channels")
@analyzer_compatibility(file_types=["png", "jpg", "jpeg", "gif", "bmp", "tiff"], requires_binary=True)
def analyze_color_channels(state: State) -> State:
    """
    Analyze individual color channels for hidden data.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_data or not PIL_AVAILABLE or not NUMPY_AVAILABLE:
        return state
    
    try:
        # Load image
        img_data = io.BytesIO(state.puzzle_data)
        img = Image.open(img_data)
        
        # Only analyze RGB/RGBA images
        if img.mode not in ('RGB', 'RGBA'):
            return state
        
        # Convert to numpy array
        img_array = np.array(img)
        
        # Analyze each color channel
        channel_names = ['Red', 'Green', 'Blue']
        for i, channel_name in enumerate(channel_names):
            if img_array.ndim != 3 or img_array.shape[2] <= i:
                continue
                
            channel = img_array[:, :, i]
            
            # Check for unusual patterns in this channel
            unique_values = np.unique(channel)
            hist, _ = np.histogram(channel, bins=256, range=(0, 256))
            
            # Get top histogram values
            top_indices = np.argsort(hist)[-5:]  # Top 5 most common values
            top_values = [(int(idx), int(hist[idx])) for idx in top_indices]
            
            # Check for unusual value distributions
            if len(unique_values) < 30:  # Unusually few unique values
                state.add_insight(
                    f"Unusual {channel_name} channel with only {len(unique_values)} unique values",
                    analyzer="image_analyzer",
                    data={"channel": channel_name, "unique_values": len(unique_values)}
                )
                
                # Extract this channel
                channel_img = Image.fromarray(channel)
                channel_buffer = io.BytesIO()
                channel_img.save(channel_buffer, format="PNG")
                
                state.add_transformation(
                    name=f"extract_{channel_name.lower()}_channel",
                    description=f"Extracted {channel_name} channel as separate image",
                    input_data=state.puzzle_data,
                    output_data=channel_buffer.getvalue(),
                    analyzer="image_analyzer"
                )
            
            # Check for binary-like data (only 2 values)
            if len(unique_values) == 2:
                state.add_insight(
                    f"{channel_name} channel contains binary-like data with values {unique_values[0]} and {unique_values[1]}",
                    analyzer="image_analyzer"
                )
                
                # Extract binary data from this channel
                binary_data = extract_binary_channel(channel, unique_values)
                
                state.add_transformation(
                    name=f"extract_binary_{channel_name.lower()}",
                    description=f"Extracted binary data from {channel_name} channel",
                    input_data=state.puzzle_data,
                    output_data=binary_data,
                    analyzer="image_analyzer"
                )
        
        # Check for unusual relationships between channels
        if img_array.ndim == 3 and img_array.shape[2] >= 3:
            r, g, b = img_array[:, :, 0], img_array[:, :, 1], img_array[:, :, 2]
            
            # Check if any two channels are identical
            if np.array_equal(r, g):
                state.add_insight(
                    "Red and Green channels are identical - unusual pattern",
                    analyzer="image_analyzer"
                )
            
            if np.array_equal(r, b):
                state.add_insight(
                    "Red and Blue channels are identical - unusual pattern",
                    analyzer="image_analyzer"
                )
            
            if np.array_equal(g, b):
                state.add_insight(
                    "Green and Blue channels are identical - unusual pattern",
                    analyzer="image_analyzer"
                )
            
            # Check for XOR relationship between channels
            r_xor_g = r ^ g
            unique_xor = np.unique(r_xor_g)
            if len(unique_xor) < 5:
                state.add_insight(
                    f"Red XOR Green has only {len(unique_xor)} unique values - possible hidden data",
                    analyzer="image_analyzer"
                )
                
                # Extract XOR channel
                xor_img = Image.fromarray(r_xor_g)
                xor_buffer = io.BytesIO()
                xor_img.save(xor_buffer, format="PNG")
                
                state.add_transformation(
                    name="extract_r_xor_g",
                    description="Extracted Red XOR Green channel",
                    input_data=state.puzzle_data,
                    output_data=xor_buffer.getvalue(),
                    analyzer="image_analyzer"
                )
    
    except Exception as e:
        state.add_insight(f"Error analyzing color channels: {e}", analyzer="image_analyzer")
    
    return state


@register_analyzer("check_pixel_patterns")
@analyzer_compatibility(file_types=["png", "jpg", "jpeg", "gif", "bmp", "tiff"], requires_binary=True)
def check_pixel_patterns(state: State) -> State:
    """
    Check for patterns in pixel data that might indicate hidden information.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_data or not PIL_AVAILABLE:
        return state
    
    try:
        # Load image
        img_data = io.BytesIO(state.puzzle_data)
        img = Image.open(img_data)
        
        # Check image size
        width, height = img.size
        
        # Check for QR code-like patterns
        if is_potential_qr_code(img):
            state.add_insight(
                "Image might contain a QR code or similar 2D barcode",
                analyzer="image_analyzer"
            )
            
            # Try to enhance potential QR code
            enhanced_qr = enhance_qr_code(img)
            
            if enhanced_qr:
                qr_buffer = io.BytesIO()
                enhanced_qr.save(qr_buffer, format="PNG")
                
                state.add_transformation(
                    name="enhance_qr_code",
                    description="Enhanced potential QR code",
                    input_data=state.puzzle_data,
                    output_data=qr_buffer.getvalue(),
                    analyzer="image_analyzer"
                )
        
        # Check for binary patterns in grayscale/1-bit images
        if img.mode in ('L', '1'):
            # Look for potential morse code or binary sequences
            morse_like = detect_morse_like_pattern(img)
            if morse_like:
                state.add_insight(
                    "Detected potential Morse code-like pattern in image",
                    analyzer="image_analyzer",
                    data=morse_like
                )
        
        # Check for hidden messages in pixel coordinates
        if width <= 1000 and height <= 1000:  # Only for reasonably sized images
            coordinate_check = check_coordinates_for_message(img)
            if coordinate_check['potential_message']:
                state.add_insight(
                    "Pixel coordinates might contain a hidden message",
                    analyzer="image_analyzer",
                    data=coordinate_check
                )
                
                # Add transformation with the coordinate data
                if 'message' in coordinate_check:
                    state.add_transformation(
                        name="extract_coordinate_message",
                        description="Extracted message from pixel coordinates",
                        input_data=state.puzzle_data,
                        output_data=coordinate_check['message'],
                        analyzer="image_analyzer"
                    )
    
    except Exception as e:
        state.add_insight(f"Error checking pixel patterns: {e}", analyzer="image_analyzer")
    
    return state


# Helper functions

def check_lsb_steganography(img: 'Image.Image') -> Dict[str, Any]:
    """
    Check for potential LSB (Least Significant Bit) steganography.
    
    Args:
        img: PIL Image
        
    Returns:
        Dict with analysis results
    """
    result = {
        'potential_steganography': False,
        'score': 0.0,
        'reasons': []
    }
    
    if not NUMPY_AVAILABLE:
        return result
    
    try:
        # Convert to numpy array
        img_array = np.array(img)
        
        # Check if image is in an appropriate mode
        if img.mode not in ('RGB', 'RGBA', 'L'):
            result['reasons'].append("Image not in appropriate mode for LSB analysis")
            return result
        
        # Extract LSBs
        if img.mode == 'L':
            # Grayscale
            lsb = img_array & 1
        else:
            # RGB/RGBA, check each channel
            channels = []
            for i in range(min(3, img_array.shape[2])):  # Only check RGB (not alpha)
                channels.append(img_array[:, :, i] & 1)
            lsb = np.stack(channels, axis=-1)
        
        # Analyze LSB patterns
        score = 0.0
        
        # Check for unusual LSB distribution
        # In natural images, LSBs should be roughly 50% 0s and 50% 1s
        if img.mode == 'L':
            flat_lsb = lsb.flatten()
            ones_ratio = np.sum(flat_lsb) / len(flat_lsb)
            
            # Check if ratio is far from 0.5
            if abs(ones_ratio - 0.5) > 0.05:
                score += 2.0
                result['reasons'].append(f"Unusual LSB distribution: {ones_ratio:.2f} 1s (expected ~0.5)")
            
            # Check for patterns or structure in the LSBs
            # Calculate the entropy of the LSB plane
            entropy = calculate_image_entropy(lsb)
            
            # Lower entropy means more structure/patterns
            if entropy < 7.5:  # Out of 8 possible bits
                score += (7.5 - entropy) * 2
                result['reasons'].append(f"LSB entropy ({entropy:.2f}) indicates potential structure")
                
            # Check for regions of constant LSB
            regions = find_constant_regions(lsb)
            if regions:
                score += min(len(regions), 3)
                result['reasons'].append(f"Found {len(regions)} regions of constant LSB value")
        else:
            # For RGB images, check each channel
            channel_scores = []
            for i in range(lsb.shape[2]):
                channel_lsb = lsb[:, :, i]
                flat_lsb = channel_lsb.flatten()
                ones_ratio = np.sum(flat_lsb) / len(flat_lsb)
                
                channel_score = 0.0
                
                # Check ratio
                if abs(ones_ratio - 0.5) > 0.05:
                    channel_score += 2.0
                
                # Check entropy
                entropy = calculate_image_entropy(channel_lsb)
                if entropy < 7.5:
                    channel_score += (7.5 - entropy) * 2
                
                # Check for regions
                regions = find_constant_regions(channel_lsb)
                if regions:
                    channel_score += min(len(regions), 3)
                
                channel_scores.append(channel_score)
            
            # Use the maximum score from any channel
            score = max(channel_scores)
            if score > 3:
                result['reasons'].append(f"Channel(s) show signs of LSB steganography")
        
        # Set the final score and result
        result['score'] = score
        result['potential_steganography'] = score > 3.0
        
        return result
    
    except Exception as e:
        logger.debug(f"Error in LSB steganography check: {e}")
        result['reasons'].append(f"Error in analysis: {str(e)}")
        return result


def extract_lsb_data(img: 'Image.Image', max_bytes: int = 1024) -> bytes:
    """
    Extract data from the least significant bits of an image.
    
    Args:
        img: PIL Image
        max_bytes: Maximum bytes to extract
        
    Returns:
        Extracted data as bytes
    """
    if not NUMPY_AVAILABLE:
        raise ValueError("NumPy is required for LSB extraction")
    
    # Convert to numpy array
    img_array = np.array(img)
    
    # Extract bits based on image mode
    if img.mode == 'L':
        # Grayscale
        bits = img_array.flatten() & 1
    else:
        # RGB/RGBA
        # Reshape to get all pixels as rows
        reshaped = img_array.reshape(-1, img_array.shape[2])
        # Extract LSB from each color channel
        bits = reshaped & 1
        # Flatten in the correct order (R1, G1, B1, R2, G2, B2, ...)
        bits = bits.flatten()
    
    # Convert bits to bytes
    num_bytes = min(len(bits) // 8, max_bytes)
    extracted = bytearray(num_bytes)
    
    for i in range(num_bytes):
        byte_bits = bits[i*8:(i+1)*8]
        byte_val = 0
        for j, bit in enumerate(byte_bits):
            byte_val |= (bit << (7-j))
        extracted[i] = byte_val
    
    return bytes(extracted)


def is_potential_text(data: bytes) -> bool:
    """
    Check if binary data might be text.
    
    Args:
        data: Binary data
        
    Returns:
        True if data might be text, False otherwise
    """
    # Count printable ASCII characters
    printable_count = sum(32 <= b <= 126 for b in data)
    
    # If more than 70% printable characters, it might be text
    return printable_count / len(data) > 0.7 if data else False


def check_for_watermark(img: 'Image.Image') -> Dict[str, Any]:
    """
    Check for visible watermarks or patterns in the image.
    
    Args:
        img: PIL Image
        
    Returns:
        Dict with analysis results
    """
    result = {
        'potential_watermark': False,
        'enhanced_watermark': None
    }
    
    try:
        # Convert image to grayscale for analysis
        if img.mode != 'L':
            gray_img = img.convert('L')
        else:
            gray_img = img
        
        # Try various enhancement techniques
        # 1. Increase contrast
        enhancer = ImageEnhance.Contrast(gray_img)
        enhanced1 = enhancer.enhance(3.0)
        
        # 2. Auto-level (normalize histogram)
        enhanced2 = ImageOps.autocontrast(gray_img, cutoff=0.5)
        
        # 3. Edge detection
        enhanced3 = gray_img.filter(ImageFilter.EDGE_ENHANCE_MORE)
        
        # Check if any enhancement reveals a pattern
        original_stats = ImageStat.Stat(gray_img)
        enhanced1_stats = ImageStat.Stat(enhanced1)
        enhanced2_stats = ImageStat.Stat(enhanced2)
        enhanced3_stats = ImageStat.Stat(enhanced3)
        
        # Look for significant differences in statistics
        if (abs(original_stats.stddev[0] - enhanced1_stats.stddev[0]) > original_stats.stddev[0] * 0.5 or
            abs(original_stats.stddev[0] - enhanced2_stats.stddev[0]) > original_stats.stddev[0] * 0.5 or
            abs(original_stats.stddev[0] - enhanced3_stats.stddev[0]) > original_stats.stddev[0] * 0.5):
            
            result['potential_watermark'] = True
            
            # Use the enhancement with the biggest difference
            diff1 = abs(original_stats.stddev[0] - enhanced1_stats.stddev[0])
            diff2 = abs(original_stats.stddev[0] - enhanced2_stats.stddev[0])
            diff3 = abs(original_stats.stddev[0] - enhanced3_stats.stddev[0])
            
            max_diff = max(diff1, diff2, diff3)
            if max_diff == diff1:
                result['enhanced_watermark'] = enhanced1
            elif max_diff == diff2:
                result['enhanced_watermark'] = enhanced2
            else:
                result['enhanced_watermark'] = enhanced3
        
        return result
    
    except Exception as e:
        logger.debug(f"Error checking for watermarks: {e}")
        return result


def extract_binary_channel(channel_array: np.ndarray, unique_values: np.ndarray) -> bytes:
    """
    Extract binary data from a channel with only two values.
    
    Args:
        channel_array: NumPy array of the channel
        unique_values: The two unique values in the channel
        
    Returns:
        Extracted binary data
    """
    # Map the two values to 0 and 1
    binary_map = {unique_values[0]: 0, unique_values[1]: 1}
    
    # Create binary array
    flat_channel = channel_array.flatten()
    bits = np.array([binary_map[val] for val in flat_channel])
    
    # Convert bits to bytes
    num_bytes = len(bits) // 8
    extracted = bytearray(num_bytes)
    
    for i in range(num_bytes):
        byte_bits = bits[i*8:(i+1)*8]
        byte_val = 0
        for j, bit in enumerate(byte_bits):
            byte_val |= (bit << (7-j))
        extracted[i] = byte_val
    
    return bytes(extracted)


def calculate_image_entropy(img_array: np.ndarray) -> float:
    """
    Calculate the entropy of an image array.
    
    Args:
        img_array: NumPy array of the image
        
    Returns:
        Entropy value
    """
    # Calculate histogram
    hist, _ = np.histogram(img_array, bins=256, range=(0, 256))
    
    # Convert to probability
    hist = hist / np.sum(hist)
    
    # Calculate entropy
    entropy = -np.sum(hist * np.log2(hist + 1e-10))  # Add small epsilon to avoid log(0)
    
    return entropy


def find_constant_regions(img_array: np.ndarray, min_size: int = 100) -> List[Dict[str, Any]]:
    """
    Find regions of constant value in an image array.
    
    Args:
        img_array: NumPy array of the image
        min_size: Minimum region size to report
        
    Returns:
        List of regions with constant value
    """
    # For simplicity, we'll use a basic algorithm
    # More advanced would use connected component analysis
    
    # Find where the array is 0 and where it's 1
    zeros = (img_array == 0)
    ones = (img_array == 1)
    
    regions = []
    
    # Check for regions of 0s
    zero_count = np.sum(zeros)
    if zero_count > min_size:
        regions.append({
            "value": 0,
            "size": int(zero_count),
            "percent": float(zero_count / img_array.size)
        })
    
    # Check for regions of 1s
    one_count = np.sum(ones)
    if one_count > min_size:
        regions.append({
            "value": 1,
            "size": int(one_count),
            "percent": float(one_count / img_array.size)
        })
    
    return regions


def is_potential_qr_code(img: 'Image.Image') -> bool:
    """
    Check if the image might contain a QR code.
    
    Args:
        img: PIL Image
        
    Returns:
        True if image might be a QR code, False otherwise
    """
    # Convert to grayscale
    if img.mode != 'L':
        gray_img = img.convert('L')
    else:
        gray_img = img
    
    # QR codes are square or nearly square
    width, height = gray_img.size
    if max(width, height) > min(width, height) * 1.2:
        return False
    
    # QR codes have high contrast and distinctive patterns
    # Binarize the image
    threshold = ImageStat.Stat(gray_img).mean[0]
    binary_img = gray_img.point(lambda p: p > threshold and 255)
    
    # Check for finder patterns (corners)
    # This is a simplistic check, real QR detection is more complex
    if NUMPY_AVAILABLE:
        try:
            binary_array = np.array(binary_img)
            
            # Check for high contrast regions
            edges = binary_array[:-1, :] != binary_array[1:, :]
            vertical_edges = np.sum(edges)
            
            edges = binary_array[:, :-1] != binary_array[:, 1:]
            horizontal_edges = np.sum(edges)
            
            total_edges = vertical_edges + horizontal_edges
            
            # QR codes have a high edge density
            edge_density = total_edges / (binary_array.shape[0] * binary_array.shape[1])
            
            return edge_density > 0.1
        except:
            pass
    
    # Fallback: check if the image is largely black and white
    stat = ImageStat.Stat(binary_img)
    extrema = stat.extrema[0]
    if extrema[1] - extrema[0] > 200:  # High contrast
        # Count black and white pixels
        histogram = binary_img.histogram()
        dark_pixels = sum(histogram[:50])  # Pixels with value 0-49
        light_pixels = sum(histogram[200:])  # Pixels with value 200-255
        
        total_pixels = width * height
        
        # QR codes have a good mix of black and white
        dark_ratio = dark_pixels / total_pixels
        light_ratio = light_pixels / total_pixels
        
        return dark_ratio > 0.2 and light_ratio > 0.2
    
    return False


def enhance_qr_code(img: 'Image.Image') -> Optional['Image.Image']:
    """
    Enhance a potential QR code in the image.
    
    Args:
        img: PIL Image
        
    Returns:
        Enhanced image or None if enhancement failed
    """
    try:
        # Convert to grayscale
        if img.mode != 'L':
            gray_img = img.convert('L')
        else:
            gray_img = img
        
        # Enhance contrast
        contrast_img = ImageEnhance.Contrast(gray_img).enhance(2.0)
        
        # Binarize
        threshold = ImageStat.Stat(contrast_img).mean[0]
        binary_img = contrast_img.point(lambda p: p > threshold and 255)
        
        # Apply some morphological operations to clean up
        binary_img = binary_img.filter(ImageFilter.MinFilter(3))
        binary_img = binary_img.filter(ImageFilter.MaxFilter(3))
        
        return binary_img
    except:
        return None


def detect_morse_like_pattern(img: 'Image.Image') -> Optional[Dict[str, Any]]:
    """
    Detect potential Morse code-like patterns in the image.
    
    Args:
        img: PIL Image
        
    Returns:
        Dict with analysis results or None if no pattern found
    """
    if not NUMPY_AVAILABLE:
        return None
    
    try:
        # Convert to grayscale and binarize
        if img.mode != 'L':
            gray_img = img.convert('L')
        else:
            gray_img = img
        
        # Binarize
        threshold = ImageStat.Stat(gray_img).mean[0]
        binary = gray_img.point(lambda p: p > threshold)
        binary_array = np.array(binary) > 0  # True for white, False for black
        
        # Look for horizontal pattern
        h_pattern = []
        for row in range(binary_array.shape[0]):
            # Get the middle row
            if row == binary_array.shape[0] // 2:
                row_vals = binary_array[row, :]
                
                # Convert to runs of black and white
                runs = []
                current_val = row_vals[0]
                run_length = 1
                
                for val in row_vals[1:]:
                    if val == current_val:
                        run_length += 1
                    else:
                        runs.append((current_val, run_length))
                        current_val = val
                        run_length = 1
                
                runs.append((current_val, run_length))
                
                # Check if we have a reasonable number of runs
                if 10 <= len(runs) <= 100:
                    h_pattern = runs
        
        # Look for vertical pattern similarly
        v_pattern = []
        for col in range(binary_array.shape[1]):
            if col == binary_array.shape[1] // 2:
                col_vals = binary_array[:, col]
                
                runs = []
                current_val = col_vals[0]
                run_length = 1
                
                for val in col_vals[1:]:
                    if val == current_val:
                        run_length += 1
                    else:
                        runs.append((current_val, run_length))
                        current_val = val
                        run_length = 1
                
                runs.append((current_val, run_length))
                
                if 10 <= len(runs) <= 100:
                    v_pattern = runs
        
        # Return the most promising pattern
        if len(h_pattern) > len(v_pattern) and len(h_pattern) >= 10:
            # Try to convert to Morse code
            morse = runs_to_morse(h_pattern)
            return {
                "type": "horizontal",
                "runs": [(bool(val), length) for val, length in h_pattern],
                "morse": morse
            }
        elif len(v_pattern) >= 10:
            morse = runs_to_morse(v_pattern)
            return {
                "type": "vertical",
                "runs": [(bool(val), length) for val, length in v_pattern],
                "morse": morse
            }
        
        return None
    except:
        return None


def runs_to_morse(runs: List[Tuple[bool, int]]) -> str:
    """
    Convert runs of black and white to potential Morse code.
    
    Args:
        runs: List of (is_white, length) tuples
        
    Returns:
        Morse code string
    """
    # Skip the first run if it's white (leading space)
    if runs and runs[0][0]:
        runs = runs[1:]
    
    # Skip the last run if it's white (trailing space)
    if runs and runs[-1][0]:
        runs = runs[:-1]
    
    # Group into black (marks) and white (spaces)
    morse = []
    
    # Get the average run length for normalization
    avg_length = sum(length for _, length in runs) / len(runs) if runs else 0
    
    for is_white, length in runs:
        if not is_white:  # Black (mark)
            if length < avg_length * 0.7:
                morse.append(".")  # dot
            else:
                morse.append("-")  # dash
        else:  # White (space)
            if length > avg_length * 1.5:
                morse.append(" ")  # word space
    
    return "".join(morse)


def check_coordinates_for_message(img: 'Image.Image') -> Dict[str, Any]:
    """
    Check if pixel coordinates with specific values might form a message.
    
    Args:
        img: PIL Image
        
    Returns:
        Dict with analysis results
    """
    result = {
        'potential_message': False
    }
    
    if not NUMPY_AVAILABLE:
        return result
    
    try:
        # Convert to numpy array
        img_array = np.array(img)
        
        # Get dimensions
        if img_array.ndim == 3:
            height, width, _ = img_array.shape
        else:
            height, width = img_array.shape
        
        # Look for pixels with unusual values
        special_pixels = []
        
        if img_array.ndim == 3:
            # For RGB/RGBA
            # Look for primary colors
            for y in range(height):
                for x in range(width):
                    pixel = img_array[y, x]
                    
                    # Check for red, green, blue, white, black
                    if (pixel[0] > 200 and pixel[1] < 50 and pixel[2] < 50) or \
                       (pixel[0] < 50 and pixel[1] > 200 and pixel[2] < 50) or \
                       (pixel[0] < 50 and pixel[1] < 50 and pixel[2] > 200) or \
                       (np.all(pixel[:3] > 240)) or \
                       (np.all(pixel[:3] < 15)):
                        special_pixels.append((x, y, tuple(pixel[:3])))
                        
                        if len(special_pixels) > 100:  # Limit to avoid too many
                            break
                
                if len(special_pixels) > 100:
                    break
        else:
            # For grayscale
            for y in range(height):
                for x in range(width):
                    pixel = img_array[y, x]
                    
                    # Check for very dark or very bright
                    if pixel < 15 or pixel > 240:
                        special_pixels.append((x, y, pixel))
                        
                        if len(special_pixels) > 100:
                            break
                
                if len(special_pixels) > 100:
                    break
        
        # If we found a reasonable number of special pixels
        if 5 <= len(special_pixels) <= 100:
            result['potential_message'] = True
            result['special_pixels'] = special_pixels
            
            # Extract coordinates and try to interpret as ASCII
            coords = [(x, y) for x, y, _ in special_pixels]
            
            # Try both x and y as ASCII values
            x_values = [x for x, _, _ in special_pixels]
            y_values = [y for _, y, _ in special_pixels]
            
            # If values are in ASCII printable range
            if all(32 <= x <= 126 for x in x_values):
                ascii_message = ''.join(chr(x) for x in x_values)
                if is_potential_text(ascii_message.encode('utf-8')):
                    result['message'] = ascii_message
            
            elif all(32 <= y <= 126 for y in y_values):
                ascii_message = ''.join(chr(y) for y in y_values)
                if is_potential_text(ascii_message.encode('utf-8')):
                    result['message'] = ascii_message
        
        return result
    
    except Exception as e:
        logger.debug(f"Error checking coordinates for message: {e}")
        return result


# Import required modules at the top level
try:
    from PIL import Image, ImageStat, ImageEnhance, ImageOps, ImageFilter
except ImportError:
    pass  # PIL availability check done in module
