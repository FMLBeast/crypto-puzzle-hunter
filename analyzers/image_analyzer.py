"""
Image analyzer for Crypto Hunter.
Analyzes images for steganography, metadata, and hidden information.
"""

import io
import string
import re
import struct
import math
import os
from collections import Counter
from pathlib import Path
from core.state import State
from analyzers.base import register_analyzer, analyzer_compatibility

# Import optional dependencies
try:
    from PIL import Image, ExifTags
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

# Import OpenCV if available
try:
    import cv2
    import numpy as np
    HAS_OPENCV = True
except ImportError:
    HAS_OPENCV = False

@register_analyzer("image_analyzer")
@analyzer_compatibility(requires_binary=True)
def analyze_image(state: State, **kwargs) -> None:
    """
    Analyze image for steganography, metadata, and hidden information.

    Args:
        state: Current puzzle state
        **kwargs: Additional parameters (ignored)

    Returns:
        Updated state
    """
    if not state.binary_data:
        return state

    # Check if the file is an image
    is_image = state.file_type in ["png", "jpg", "jpeg", "gif", "bmp", "tiff", "webp"]

    if not is_image:
        # Try to detect image from magic bytes
        magic_bytes = state.binary_data[:8]
        if magic_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
            is_image = True
            state.file_type = "png"
        elif magic_bytes.startswith(b"\xff\xd8"):
            is_image = True
            state.file_type = "jpeg"
        elif magic_bytes.startswith(b"GIF87a") or magic_bytes.startswith(b"GIF89a"):
            is_image = True
            state.file_type = "gif"
        elif magic_bytes.startswith(b"BM"):
            is_image = True
            state.file_type = "bmp"

    if not is_image:
        state.add_insight(
            "File does not appear to be an image, skipping image analysis",
            analyzer="image_analyzer"
        )
        return state

    state.add_insight(
        f"Analyzing {state.file_type} image ({state.file_size} bytes)",
        analyzer="image_analyzer"
    )

    # Analyze image if PIL is available
    if HAS_PIL:
        analyze_with_pil(state)
    else:
        state.add_insight(
            "PIL library not available, image analysis limited",
            analyzer="image_analyzer"
        )
        analyze_without_pil(state)

    # Look for hidden text in the image
    extract_text_from_image(state)

    # Check for steganography
    check_lsb_steganography(state)

    # Check for hidden files in the image
    check_embedded_files(state)

    return state

def analyze_with_pil(state: State) -> None:
    """
    Analyze image using the PIL library.

    Args:
        state: Current puzzle state
    """
    try:
        # Open the image
        image_data = io.BytesIO(state.binary_data)
        image = Image.open(image_data)

        # Get basic image information
        width, height = image.size
        mode = image.mode
        format = image.format

        state.add_insight(
            f"Image dimensions: {width}x{height}, Mode: {mode}, Format: {format}",
            analyzer="image_analyzer"
        )

        # Analyze color information
        if mode == "RGB" or mode == "RGBA":
            analyze_rgb_image(state, image)
        elif mode == "L":
            analyze_grayscale_image(state, image)
        elif mode == "P":
            analyze_palette_image(state, image)

        # Analyze image metadata
        analyze_image_metadata(state, image)

    except Exception as e:
        state.add_insight(
            f"Error analyzing image with PIL: {e}",
            analyzer="image_analyzer"
        )

def analyze_without_pil(state: State) -> None:
    """
    Analyze image without using the PIL library.

    Args:
        state: Current puzzle state
    """
    # Basic analysis of image headers
    if state.file_type == "png":
        analyze_png_header(state)
    elif state.file_type in ["jpg", "jpeg"]:
        analyze_jpeg_header(state)
    elif state.file_type == "gif":
        analyze_gif_header(state)
    elif state.file_type == "bmp":
        analyze_bmp_header(state)

def analyze_rgb_image(state: State, image) -> None:
    """
    Analyze an RGB image.

    Args:
        state: Current puzzle state
        image: PIL Image object
    """
    try:
        # Get color statistics
        pixels = list(image.getdata())
        total_pixels = len(pixels)

        if total_pixels == 0:
            return

        # Count unique colors
        unique_colors = len(set(pixels))

        state.add_insight(
            f"Image has {unique_colors} unique colors out of {total_pixels} total pixels",
            analyzer="image_analyzer"
        )

        # Check for unusual color patterns
        if unique_colors < 10 and total_pixels > 1000:
            state.add_insight(
                "Image has unusually few unique colors, may contain hidden information",
                analyzer="image_analyzer"
            )

        # Check for patterns in least significant bits
        has_lsb_pattern = check_lsb_pattern(pixels)
        if has_lsb_pattern:
            state.add_insight(
                "Detected potential pattern in least significant bits, may contain steganography",
                analyzer="image_analyzer"
            )

        # Analyze color distribution
        red = [pixel[0] for pixel in pixels if len(pixel) >= 1]
        green = [pixel[1] for pixel in pixels if len(pixel) >= 2]
        blue = [pixel[2] for pixel in pixels if len(pixel) >= 3]

        # Check for uneven color distribution
        r_std_dev = calculate_std_dev(red)
        g_std_dev = calculate_std_dev(green)
        b_std_dev = calculate_std_dev(blue)

        if max(r_std_dev, g_std_dev, b_std_dev) / min(r_std_dev, g_std_dev, b_std_dev) > 2:
            state.add_insight(
                "Uneven color channel distribution detected, may indicate hidden data",
                analyzer="image_analyzer"
            )

    except Exception as e:
        state.add_insight(
            f"Error analyzing RGB image: {e}",
            analyzer="image_analyzer"
        )

def analyze_grayscale_image(state: State, image) -> None:
    """
    Analyze a grayscale image.

    Args:
        state: Current puzzle state
        image: PIL Image object
    """
    try:
        # Get grayscale statistics
        pixels = list(image.getdata())
        total_pixels = len(pixels)

        if total_pixels == 0:
            return

        # Count unique gray values
        unique_values = len(set(pixels))

        state.add_insight(
            f"Grayscale image has {unique_values} unique values out of {total_pixels} total pixels",
            analyzer="image_analyzer"
        )

        # Check for unusual patterns
        if unique_values < 5 and total_pixels > 1000:
            state.add_insight(
                "Grayscale image has unusually few unique values, may contain hidden information",
                analyzer="image_analyzer"
            )

        # Check for patterns in least significant bits
        has_lsb_pattern = check_lsb_pattern(pixels)
        if has_lsb_pattern:
            state.add_insight(
                "Detected potential pattern in least significant bits, may contain steganography",
                analyzer="image_analyzer"
            )

    except Exception as e:
        state.add_insight(
            f"Error analyzing grayscale image: {e}",
            analyzer="image_analyzer"
        )

def analyze_palette_image(state: State, image) -> None:
    """
    Analyze a palettized image.

    Args:
        state: Current puzzle state
        image: PIL Image object
    """
    try:
        # Get palette information
        if not hasattr(image, "palette"):
            return

        palette_data = image.palette.palette

        if not palette_data:
            return

        # Count colors in the palette
        palette_size = len(palette_data) // 3

        state.add_insight(
            f"Image uses a color palette with {palette_size} colors",
            analyzer="image_analyzer"
        )

        # Check for hidden data in unused palette entries
        pixels = list(image.getdata())
        used_indices = set(pixels)

        if len(used_indices) < palette_size:
            state.add_insight(
                f"Image uses {len(used_indices)} colors out of {palette_size} in the palette, unused entries may contain hidden data",
                analyzer="image_analyzer"
            )

    except Exception as e:
        state.add_insight(
            f"Error analyzing palette image: {e}",
            analyzer="image_analyzer"
        )

def analyze_image_metadata(state: State, image) -> None:
    """
    Analyze image metadata.

    Args:
        state: Current puzzle state
        image: PIL Image object
    """
    try:
        # Check for EXIF data
        if hasattr(image, "_getexif") and image._getexif():
            exif_data = image._getexif()

            # List of interesting EXIF tags
            interesting_tags = {
                'Artist', 'Copyright', 'ImageDescription', 'Make', 'Model',
                'Software', 'DateTime', 'DateTimeOriginal', 'GPSInfo',
                'UserComment'
            }

            # Convert tag IDs to names
            exif_info = {}
            for tag_id, value in exif_data.items():
                tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                exif_info[tag_name] = value

            # Look for interesting tags
            found_tags = []
            for tag in interesting_tags:
                if tag in exif_info:
                    found_tags.append(f"{tag}: {exif_info[tag]}")

            if found_tags:
                state.add_insight(
                    f"Found {len(found_tags)} interesting EXIF tags",
                    analyzer="image_analyzer"
                )

                # Add transformation with EXIF data
                state.add_transformation(
                    name="EXIF Metadata",
                    description="EXIF metadata extracted from the image",
                    input_data=f"Image file ({state.file_size} bytes)",
                    output_data="\n".join(found_tags),
                    analyzer="image_analyzer"
                )

        # Check for PNG text chunks
        if image.format == "PNG" and hasattr(image, "text") and image.text:
            text_chunks = []
            for key, value in image.text.items():
                text_chunks.append(f"{key}: {value}")

            if text_chunks:
                state.add_insight(
                    f"Found {len(text_chunks)} PNG text chunks",
                    analyzer="image_analyzer"
                )

                # Add transformation with text chunks
                state.add_transformation(
                    name="PNG Text Chunks",
                    description="Text chunks extracted from the PNG image",
                    input_data=f"PNG image ({state.file_size} bytes)",
                    output_data="\n".join(text_chunks),
                    analyzer="image_analyzer"
                )

    except Exception as e:
        state.add_insight(
            f"Error analyzing image metadata: {e}",
            analyzer="image_analyzer"
        )

def analyze_png_header(state: State) -> None:
    """
    Analyze PNG header without using PIL.

    Args:
        state: Current puzzle state
    """
    try:
        # Check for PNG signature
        if not state.binary_data.startswith(b"\x89PNG\r\n\x1a\n"):
            state.add_insight(
                "File does not start with a valid PNG signature",
                analyzer="image_analyzer"
            )
            return

        # Parse PNG chunks
        chunk_data = parse_png_chunks(state.binary_data)

        if not chunk_data:
            return

        # Get image dimensions from IHDR chunk
        ihdr_chunk = next((chunk for chunk in chunk_data if chunk["type"] == "IHDR"), None)

        if ihdr_chunk and len(ihdr_chunk["data"]) >= 8:
            width = int.from_bytes(ihdr_chunk["data"][0:4], byteorder="big")
            height = int.from_bytes(ihdr_chunk["data"][4:8], byteorder="big")
            bit_depth = ihdr_chunk["data"][8] if len(ihdr_chunk["data"]) > 8 else None
            color_type = ihdr_chunk["data"][9] if len(ihdr_chunk["data"]) > 9 else None

            dimensions_info = f"Image dimensions: {width}x{height}"
            if bit_depth is not None:
                dimensions_info += f", Bit depth: {bit_depth}"
            if color_type is not None:
                color_type_name = {
                    0: "Grayscale",
                    2: "RGB",
                    3: "Palette",
                    4: "Grayscale with alpha",
                    6: "RGBA"
                }.get(color_type, f"Unknown ({color_type})")
                dimensions_info += f", Color type: {color_type_name}"

            state.add_insight(dimensions_info, analyzer="image_analyzer")

        # Look for text chunks
        text_chunks = [chunk for chunk in chunk_data if chunk["type"] in ["tEXt", "iTXt", "zTXt"]]

        if text_chunks:
            state.add_insight(
                f"Found {len(text_chunks)} text chunks in PNG file",
                analyzer="image_analyzer"
            )

            # Try to extract text
            for chunk in text_chunks:
                if chunk["type"] == "tEXt" and len(chunk["data"]) > 1:
                    # tEXt chunks: keyword\0text
                    null_pos = chunk["data"].find(b"\0")
                    if null_pos != -1:
                        keyword = chunk["data"][:null_pos].decode("latin1", errors="replace")
                        text = chunk["data"][null_pos+1:].decode("latin1", errors="replace")

                        state.add_transformation(
                            name=f"PNG Text Chunk: {keyword}",
                            description=f"Text from PNG tEXt chunk with keyword '{keyword}'",
                            input_data=f"PNG image ({state.file_size} bytes)",
                            output_data=text,
                            analyzer="image_analyzer"
                        )

        # Look for unusual chunks
        standard_chunks = {"IHDR", "PLTE", "IDAT", "IEND", "tRNS", "cHRM", "gAMA", "iCCP", "sBIT", "sRGB", "tEXt", "iTXt", "zTXt", "bKGD", "hIST", "pHYs", "sPLT", "tIME"}
        unusual_chunks = [chunk for chunk in chunk_data if chunk["type"] not in standard_chunks]

        if unusual_chunks:
            state.add_insight(
                f"Found {len(unusual_chunks)} non-standard chunks in PNG file: {', '.join(chunk['type'] for chunk in unusual_chunks)}",
                analyzer="image_analyzer"
            )

            # Add transformation with unusual chunks
            unusual_chunk_info = "\n".join([
                f"Chunk: {chunk['type']}, Length: {len(chunk['data'])} bytes"
                for chunk in unusual_chunks
            ])

            state.add_transformation(
                name="Unusual PNG Chunks",
                description="Non-standard chunks found in the PNG file",
                input_data=f"PNG image ({state.file_size} bytes)",
                output_data=unusual_chunk_info,
                analyzer="image_analyzer"
            )

    except Exception as e:
        state.add_insight(
            f"Error analyzing PNG header: {e}",
            analyzer="image_analyzer"
        )

def analyze_jpeg_header(state: State) -> None:
    """
    Analyze JPEG header without using PIL.

    Args:
        state: Current puzzle state
    """
    try:
        # Check for JPEG signature
        if not state.binary_data.startswith(b"\xff\xd8"):
            state.add_insight(
                "File does not start with a valid JPEG signature",
                analyzer="image_analyzer"
            )
            return

        # Parse JPEG segments
        segments = parse_jpeg_segments(state.binary_data)

        if not segments:
            return

        # Look for dimensions in SOF segments
        sof_segments = [seg for seg in segments if seg["marker"] in range(0xC0, 0xC4)]

        if sof_segments and len(sof_segments[0]["data"]) >= 5:
            segment = sof_segments[0]
            precision = segment["data"][0]
            height = int.from_bytes(segment["data"][1:3], byteorder="big")
            width = int.from_bytes(segment["data"][3:5], byteorder="big")

            state.add_insight(
                f"Image dimensions: {width}x{height}, Precision: {precision} bits",
                analyzer="image_analyzer"
            )

        # Look for EXIF data
        app1_segments = [seg for seg in segments if seg["marker"] == 0xE1]

        for segment in app1_segments:
            if segment["data"].startswith(b"Exif\0\0"):
                state.add_insight(
                    "Found EXIF data in JPEG file",
                    analyzer="image_analyzer"
                )
                break

        # Look for comment segments
        comment_segments = [seg for seg in segments if seg["marker"] == 0xFE]

        if comment_segments:
            state.add_insight(
                f"Found {len(comment_segments)} comment segments in JPEG file",
                analyzer="image_analyzer"
            )

            # Try to extract comments
            for i, segment in enumerate(comment_segments):
                try:
                    comment = segment["data"].decode("utf-8", errors="replace")

                    state.add_transformation(
                        name=f"JPEG Comment {i+1}",
                        description=f"Comment from JPEG file",
                        input_data=f"JPEG image ({state.file_size} bytes)",
                        output_data=comment,
                        analyzer="image_analyzer"
                    )
                except:
                    pass

        # Look for unusual segments
        standard_markers = {0xD8, 0xE0, 0xE1, 0xDB, 0xC0, 0xC2, 0xC4, 0xDA, 0xD9, 0xFE}
        unusual_segments = [seg for seg in segments if seg["marker"] not in standard_markers]

        if unusual_segments:
            state.add_insight(
                f"Found {len(unusual_segments)} unusual segments in JPEG file",
                analyzer="image_analyzer"
            )

            # Add transformation with unusual segments
            unusual_segment_info = "\n".join([
                f"Marker: 0x{seg['marker']:02X}, Length: {len(seg['data'])} bytes"
                for seg in unusual_segments
            ])

            state.add_transformation(
                name="Unusual JPEG Segments",
                description="Non-standard segments found in the JPEG file",
                input_data=f"JPEG image ({state.file_size} bytes)",
                output_data=unusual_segment_info,
                analyzer="image_analyzer"
            )

    except Exception as e:
        state.add_insight(
            f"Error analyzing JPEG header: {e}",
            analyzer="image_analyzer"
        )

def analyze_gif_header(state: State) -> None:
    """
    Analyze GIF header without using PIL.

    Args:
        state: Current puzzle state
    """
    try:
        # Check for GIF signature
        if not (state.binary_data.startswith(b"GIF87a") or state.binary_data.startswith(b"GIF89a")):
            state.add_insight(
                "File does not start with a valid GIF signature",
                analyzer="image_analyzer"
            )
            return

        # Get GIF version
        version = state.binary_data[3:6].decode("ascii")

        # Parse width and height
        if len(state.binary_data) >= 14:
            width = int.from_bytes(state.binary_data[6:8], byteorder="little")
            height = int.from_bytes(state.binary_data[8:10], byteorder="little")

            state.add_insight(
                f"GIF version: {version}, Dimensions: {width}x{height}",
                analyzer="image_analyzer"
            )
        else:
            state.add_insight(
                f"GIF version: {version}, file may be truncated",
                analyzer="image_analyzer"
            )

        # Look for comments
        comment_blocks = find_gif_comments(state.binary_data)

        if comment_blocks:
            state.add_insight(
                f"Found {len(comment_blocks)} comment blocks in GIF file",
                analyzer="image_analyzer"
            )

            # Add transformation with comments
            comments_text = "\n".join([
                f"Comment block {i+1}:\n{comment.decode('ascii', errors='replace')}"
                for i, comment in enumerate(comment_blocks)
            ])

            state.add_transformation(
                name="GIF Comments",
                description="Comment blocks found in the GIF file",
                input_data=f"GIF image ({state.file_size} bytes)",
                output_data=comments_text,
                analyzer="image_analyzer"
            )

        # Check for multiple frames
        frame_count = count_gif_frames(state.binary_data)

        if frame_count > 1:
            state.add_insight(
                f"GIF contains {frame_count} frames (animated)",
                analyzer="image_analyzer"
            )

    except Exception as e:
        state.add_insight(
            f"Error analyzing GIF header: {e}",
            analyzer="image_analyzer"
        )

def analyze_bmp_header(state: State) -> None:
    """
    Analyze BMP header without using PIL.

    Args:
        state: Current puzzle state
    """
    try:
        # Check for BMP signature
        if not state.binary_data.startswith(b"BM"):
            state.add_insight(
                "File does not start with a valid BMP signature",
                analyzer="image_analyzer"
            )
            return

        # Parse BMP header
        if len(state.binary_data) >= 54:  # Minimum size for BMP header
            # Get dimensions
            width = int.from_bytes(state.binary_data[18:22], byteorder="little", signed=True)
            height = int.from_bytes(state.binary_data[22:26], byteorder="little", signed=True)

            # Get bit depth
            bit_depth = int.from_bytes(state.binary_data[28:30], byteorder="little")

            # Get compression method
            compression = int.from_bytes(state.binary_data[30:34], byteorder="little")
            compression_name = {
                0: "BI_RGB (none)",
                1: "BI_RLE8",
                2: "BI_RLE4",
                3: "BI_BITFIELDS",
                4: "BI_JPEG",
                5: "BI_PNG"
            }.get(compression, f"Unknown ({compression})")

            state.add_insight(
                f"BMP dimensions: {width}x{abs(height)}, Bit depth: {bit_depth}, Compression: {compression_name}",
                analyzer="image_analyzer"
            )

            # Check for unusual bit depths
            if bit_depth not in [1, 4, 8, 16, 24, 32]:
                state.add_insight(
                    f"Unusual bit depth: {bit_depth}, may indicate hidden data",
                    analyzer="image_analyzer"
                )
        else:
            state.add_insight(
                "BMP file too small to contain valid header",
                analyzer="image_analyzer"
            )

    except Exception as e:
        state.add_insight(
            f"Error analyzing BMP header: {e}",
            analyzer="image_analyzer"
        )

def extract_text_from_image(state: State) -> None:
    """
    Extract potential text from the image.

    Args:
        state: Current puzzle state
    """
    # Look for ASCII or UTF-8 text in the image data
    try:
        # Skip the header for common image formats
        data = state.binary_data
        header_size = 0

        if state.file_type == "png":
            # Skip PNG signature and IHDR chunk
            header_size = 24
        elif state.file_type in ["jpg", "jpeg"]:
            # JPEG has variable header size, just skip signature
            header_size = 2
        elif state.file_type == "gif":
            # Skip GIF signature and logical screen descriptor
            header_size = 13
        elif state.file_type == "bmp":
            # Skip BMP header
            header_size = 54

        # Skip header if large enough
        if len(data) > header_size:
            data = data[header_size:]

        # Look for ASCII text
        ascii_strings = find_strings(data, min_length=5)

        if ascii_strings:
            state.add_insight(
                f"Found {len(ascii_strings)} potential text strings in the image data",
                analyzer="image_analyzer"
            )

            # Filter out common image processing strings
            filtered_strings = []
            for string, _ in ascii_strings:
                # Skip common strings found in image files
                if not any(common in string.lower() for common in [
                    "adobe", "photoshop", "gimp", "png", "jpeg", "exif", "http", "xml", "pict",
                    "unicode", "apple", "windows", "microsoft"
                ]):
                    filtered_strings.append(string)

            if filtered_strings:
                # Add transformation with extracted strings
                if len(filtered_strings) > 20:
                    # Too many strings, just show the first 20
                    text = "\n".join(filtered_strings[:20]) + f"\n\n[...and {len(filtered_strings)-20} more...]"
                else:
                    text = "\n".join(filtered_strings)

                state.add_transformation(
                    name="Image Text Extraction",
                    description="Text strings found in the image data",
                    input_data=f"Image file ({state.file_size} bytes)",
                    output_data=text,
                    analyzer="image_analyzer"
                )

    except Exception as e:
        state.add_insight(
            f"Error extracting text from image: {e}",
            analyzer="image_analyzer"
        )

def check_lsb_steganography(state: State, technique: str = "all", **kwargs) -> None:
    """
    Check for least significant bit (LSB) steganography.

    Args:
        state: Current puzzle state
        technique: LSB extraction technique to use (options: "all", "rgb", "channel", "plane")
        **kwargs: Additional parameters (file path can be specified but is ignored)
    """
    # Only perform LSB analysis if PIL is available
    if not HAS_PIL:
        return

    # Ignore file parameter if provided (for compatibility)
    if 'file' in kwargs:
        state.add_insight(
            "Note: 'file' parameter is not needed for LSB analysis, using binary data from state",
            analyzer="image_analyzer"
        )

    try:
        # Open the image
        image_data = io.BytesIO(state.binary_data)
        image = Image.open(image_data)

        # Check image mode and provide appropriate message
        if image.mode not in ["RGB", "RGBA", "LA"]:
            state.add_insight(
                f"Image mode {image.mode} is not optimal for LSB steganography analysis. Best results are with RGB/RGBA images.",
                analyzer="image_analyzer"
            )
            if image.mode == "L":  # Grayscale
                state.add_insight(
                    "Performing LSB analysis on grayscale image (single channel only)",
                    analyzer="image_analyzer"
                )
            elif image.mode == "LA":  # Grayscale with alpha
                state.add_insight(
                    "Performing LSB analysis on grayscale image with alpha channel",
                    analyzer="image_analyzer"
                )
            elif image.mode == "P":  # Palette
                state.add_insight(
                    "LSB analysis on palette images may not be reliable",
                    analyzer="image_analyzer"
                )
                return

        # Get image dimensions
        width, height = image.size
        total_pixels = width * height

        # Determine analysis approach based on image size
        if total_pixels > 10000:
            state.add_insight(
                f"Large image detected ({width}x{height}). Performing targeted LSB analysis.",
                analyzer="image_analyzer"
            )
            # For large images, analyze a sample plus specific regions
            sample_size = 5000  # Increased sample size
            regions_to_check = [
                (0, 0, width//10, height//10),  # Top-left corner
                (width-width//10, 0, width, height//10),  # Top-right corner
                (0, height-height//10, width//10, height),  # Bottom-left corner
                (width-width//10, height-height//10, width, height),  # Bottom-right corner
                (width//3, height//3, 2*width//3, 2*height//3)  # Center region
            ]
        else:
            # For smaller images, analyze the entire image
            sample_size = total_pixels
            regions_to_check = []

        # Determine which techniques to use
        techniques = []
        if technique == "all":
            techniques = ["rgb", "channel", "plane"]
        else:
            techniques = [technique]

        # Perform LSB extraction for each technique
        for tech in techniques:
            if tech == "rgb" and image.mode in ["RGB", "RGBA"]:
                # Standard RGB LSB extraction (all channels combined)
                lsb_data = extract_lsb_rgb(image, sample_size)
                analyze_lsb_data(state, lsb_data, "RGB combined")

                # Check specific regions if needed
                for i, region in enumerate(regions_to_check):
                    region_lsb = extract_lsb_rgb_region(image, region)
                    analyze_lsb_data(state, region_lsb, f"Region {i+1}")

            elif tech == "channel" and image.mode in ["RGB", "RGBA"]:
                # Per-channel LSB extraction
                channels = ["Red", "Green", "Blue"]
                for i, channel in enumerate(channels):
                    channel_lsb = extract_lsb_channel(image, i, sample_size)
                    analyze_lsb_data(state, channel_lsb, channel)

            elif tech == "plane" and image.mode in ["RGB", "RGBA", "L", "LA"]:
                # Bit plane extraction (looking at the same bit position across pixels)
                for bit_pos in range(8):  # Check all 8 bit positions
                    plane_data = extract_bit_plane(image, bit_pos, sample_size)
                    if has_binary_pattern(plane_data):
                        state.add_insight(
                            f"Detected pattern in bit plane {bit_pos}",
                            analyzer="image_analyzer"
                        )
                        analyze_lsb_data(state, plane_data, f"Bit plane {bit_pos}")

            # For grayscale images
            if image.mode in ["L", "LA"] and tech in ["rgb", "channel"]:
                # Extract LSBs from grayscale
                gray_lsb = extract_lsb_grayscale(image, sample_size)
                analyze_lsb_data(state, gray_lsb, "Grayscale")

    except Exception as e:
        state.add_insight(
            f"Error checking for LSB steganography: {e}",
            analyzer="image_analyzer"
        )

def extract_lsb_rgb(image, sample_size):
    """Extract LSBs from RGB channels of an image."""
    width, height = image.size
    lsb_data = ""

    for i in range(min(sample_size, width * height)):
        # Get pixel coordinates
        x = (i % width)
        y = (i // width)

        # Get pixel value
        pixel = image.getpixel((x, y))

        # Extract LSB from each channel
        if len(pixel) >= 3:  # RGB or RGBA
            r_lsb = pixel[0] & 1
            g_lsb = pixel[1] & 1
            b_lsb = pixel[2] & 1

            # Append LSBs to data
            lsb_data += str(r_lsb) + str(g_lsb) + str(b_lsb)

    return lsb_data

def extract_lsb_rgb_region(image, region):
    """Extract LSBs from a specific region of an image."""
    left, top, right, bottom = region
    lsb_data = ""

    for y in range(top, bottom):
        for x in range(left, right):
            # Get pixel value
            pixel = image.getpixel((x, y))

            # Extract LSB from each channel
            if len(pixel) >= 3:  # RGB or RGBA
                r_lsb = pixel[0] & 1
                g_lsb = pixel[1] & 1
                b_lsb = pixel[2] & 1

                # Append LSBs to data
                lsb_data += str(r_lsb) + str(g_lsb) + str(b_lsb)

    return lsb_data

def extract_lsb_channel(image, channel_idx, sample_size):
    """Extract LSBs from a specific channel of an image."""
    width, height = image.size
    lsb_data = ""

    for i in range(min(sample_size, width * height)):
        # Get pixel coordinates
        x = (i % width)
        y = (i // width)

        # Get pixel value
        pixel = image.getpixel((x, y))

        # Extract LSB from the specified channel
        if len(pixel) > channel_idx:
            lsb = pixel[channel_idx] & 1
            lsb_data += str(lsb)

    return lsb_data

def extract_bit_plane(image, bit_position, sample_size):
    """Extract a specific bit plane from an image."""
    width, height = image.size
    bit_data = ""

    for i in range(min(sample_size, width * height)):
        # Get pixel coordinates
        x = (i % width)
        y = (i // width)

        # Get pixel value
        pixel = image.getpixel((x, y))

        # For grayscale images
        if isinstance(pixel, int):
            bit = (pixel >> bit_position) & 1
            bit_data += str(bit)
        # For RGB/RGBA images, check all channels
        elif len(pixel) >= 3:
            for j in range(3):  # Check R, G, B channels
                bit = (pixel[j] >> bit_position) & 1
                bit_data += str(bit)

    return bit_data

def extract_lsb_grayscale(image, sample_size):
    """Extract LSBs from a grayscale image."""
    width, height = image.size
    lsb_data = ""

    for i in range(min(sample_size, width * height)):
        # Get pixel coordinates
        x = (i % width)
        y = (i // width)

        # Get pixel value
        pixel = image.getpixel((x, y))

        # For grayscale images
        if isinstance(pixel, int):
            lsb = pixel & 1
            lsb_data += str(lsb)
        # For grayscale with alpha
        elif len(pixel) >= 1:
            lsb = pixel[0] & 1
            lsb_data += str(lsb)

    return lsb_data

def analyze_lsb_data(state, lsb_data, source_description):
    """Analyze extracted LSB data for patterns and content."""
    if not lsb_data or len(lsb_data) < 24:  # Need at least a few bytes
        return

    # Check if LSBs form a pattern
    if has_binary_pattern(lsb_data):
        state.add_insight(
            f"Detected pattern in {source_description} LSBs, likely contains steganographic data",
            analyzer="image_analyzer"
        )

        # Try to interpret LSB data as ASCII
        try:
            # Group bits into bytes
            lsb_bytes = []
            for i in range(0, len(lsb_data), 8):
                if i + 8 <= len(lsb_data):
                    byte = int(lsb_data[i:i+8], 2)
                    lsb_bytes.append(byte)

            # Convert bytes to ASCII where possible
            ascii_data = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in lsb_bytes)

            # Check if result contains readable text
            common_words = ["the", "and", "ing", "tion", "for", "that", "have", "with"]
            if any(word in ascii_data.lower() for word in common_words):
                state.add_insight(
                    f"LSB data from {source_description} appears to contain readable text",
                    analyzer="image_analyzer"
                )

                state.add_transformation(
                    name=f"LSB Steganography ({source_description})",
                    description=f"Text extracted from least significant bits in {source_description}",
                    input_data=f"Image file ({state.file_size} bytes)",
                    output_data=ascii_data,
                    analyzer="image_analyzer"
                )
            else:
                # Check for other encodings (hex, base64, etc.)
                from analyzers.encoding_analyzer import detect_encoding
                encoding_result = detect_encoding(ascii_data)

                if encoding_result:
                    state.add_insight(
                        f"LSB data from {source_description} may be encoded as {encoding_result}",
                        analyzer="image_analyzer"
                    )

                # Show raw extracted bytes
                state.add_transformation(
                    name=f"LSB Data ({source_description})",
                    description=f"Data extracted from least significant bits in {source_description}",
                    input_data=f"Image file ({state.file_size} bytes)",
                    output_data=f"Binary: {lsb_data[:100]}...\nHex: {bytes(lsb_bytes).hex()[:100]}...\nASCII: {ascii_data[:100]}...",
                    analyzer="image_analyzer"
                )

                # Check for potential cryptocurrency addresses or hashes
                if len(ascii_data) >= 26:
                    from analyzers.blockchain_analyzer import detect_crypto_addresses
                    addresses = detect_crypto_addresses(ascii_data)
                    if addresses:
                        state.add_insight(
                            f"Found potential cryptocurrency addresses in LSB data from {source_description}",
                            analyzer="image_analyzer"
                        )
                        state.add_transformation(
                            name=f"Crypto Addresses in LSB ({source_description})",
                            description=f"Cryptocurrency addresses found in LSB data from {source_description}",
                            input_data=f"LSB data from image",
                            output_data="\n".join(addresses),
                            analyzer="image_analyzer"
                        )
        except Exception as e:
            state.add_insight(
                f"Error interpreting LSB data from {source_description}: {e}",
                analyzer="image_analyzer"
            )

def check_embedded_files(state: State) -> None:
    """
    Check for embedded files in the image.

    Args:
        state: Current puzzle state
    """
    try:
        # Look for file signatures
        data = state.binary_data

        # Common file signatures to look for
        signatures = {
            b"PK\x03\x04": "ZIP archive",
            b"Rar!\x1A\x07": "RAR archive",
            b"\x1F\x8B\x08": "GZIP file",
            b"BZh": "BZIP2 file",
            b"7z\xBC\xAF\x27\x1C": "7-Zip archive",
            b"\x50\x4B\x03\x04\x14\x00\x06\x00": "DOCX/XLSX/PPTX file",
            b"%PDF": "PDF document",
            b"\xFF\xD8\xFF": "JPEG image",
            b"\x89PNG\r\n\x1A\n": "PNG image",
            b"GIF87a": "GIF image",
            b"GIF89a": "GIF image",
            b"ID3": "MP3 audio",
            b"\x00\x00\x00\x18\x66\x74\x79\x70": "MP4 video"
        }

        embedded_files = []

        for signature, file_type in signatures.items():
            pos = data.find(signature)

            # Skip if signature is at the beginning (it's the image itself)
            if pos > 0:
                embedded_files.append((pos, file_type, signature))

        if embedded_files:
            state.add_insight(
                f"Found {len(embedded_files)} potential embedded files in the image",
                analyzer="image_analyzer"
            )

            # Add transformation with embedded file information
            embedded_info = "\n".join([
                f"Position: {pos} (0x{pos:X}), Type: {file_type}"
                for pos, file_type, _ in embedded_files
            ])

            state.add_transformation(
                name="Embedded Files",
                description="Potential embedded files found in the image",
                input_data=f"Image file ({state.file_size} bytes)",
                output_data=embedded_info,
                analyzer="image_analyzer"
            )

            # Try to extract the first embedded file
            if embedded_files:
                pos, file_type, signature = embedded_files[0]

                # For common archive formats, try to find the end
                end_pos = None
                if file_type == "ZIP archive":
                    # Look for end of central directory record
                    eocd_sig = b"\x50\x4B\x05\x06"
                    eocd_pos = data.rfind(eocd_sig)
                    if eocd_pos != -1:
                        # End of ZIP is 22 bytes after EOCD signature
                        end_pos = eocd_pos + 22

                # If end position found, extract the file
                if end_pos and end_pos > pos:
                    embedded_data = data[pos:end_pos]

                    state.add_transformation(
                        name=f"Extracted {file_type}",
                        description=f"Embedded file extracted from position {pos}",
                        input_data=f"Image file ({state.file_size} bytes)",
                        output_data=f"Extracted {len(embedded_data)} bytes of {file_type} data at position {pos}.\n\nHex signature: {embedded_data[:16].hex()}",
                        analyzer="image_analyzer"
                    )

    except Exception as e:
        state.add_insight(
            f"Error checking for embedded files: {e}",
            analyzer="image_analyzer"
        )

# Utility functions

def parse_png_chunks(data: bytes) -> list:
    """
    Parse PNG file chunks.

    Args:
        data: PNG file data

    Returns:
        List of chunks (each a dict with type and data)
    """
    if len(data) < 8 or not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return []

    chunks = []
    pos = 8  # Skip PNG signature

    while pos < len(data):
        if pos + 8 > len(data):
            break

        # Read chunk length and type
        chunk_length = int.from_bytes(data[pos:pos+4], byteorder="big")
        chunk_type = data[pos+4:pos+8].decode("ascii", errors="replace")

        # Ensure chunk data doesn't exceed file size
        if pos + 12 + chunk_length > len(data):
            break

        # Read chunk data (excluding CRC)
        chunk_data = data[pos+8:pos+8+chunk_length]

        chunks.append({
            "type": chunk_type,
            "data": chunk_data
        })

        # Move to next chunk
        pos += 12 + chunk_length  # 4 (length) + 4 (type) + chunk_length + 4 (CRC)

        # Stop if IEND chunk found
        if chunk_type == "IEND":
            break

    return chunks

def parse_jpeg_segments(data: bytes) -> list:
    """
    Parse JPEG file segments.

    Args:
        data: JPEG file data

    Returns:
        List of segments (each a dict with marker and data)
    """
    if len(data) < 2 or not data.startswith(b"\xff\xd8"):
        return []

    segments = []
    pos = 2  # Skip JPEG signature

    while pos < len(data):
        if data[pos] != 0xFF:
            pos += 1
            continue

        if pos + 1 >= len(data):
            break

        marker = data[pos+1]

        # Skip padding markers
        if marker == 0x00:
            pos += 2
            continue

        # Check if it's a standalone marker
        if marker in [0xD9]:  # EOI marker
            segments.append({
                "marker": marker,
                "data": b""
            })
            break

        # For other markers, read length
        if pos + 4 > len(data):
            break

        segment_length = int.from_bytes(data[pos+2:pos+4], byteorder="big")

        # Ensure segment doesn't exceed file size
        if pos + 2 + segment_length > len(data):
            break

        # Read segment data
        segment_data = data[pos+4:pos+2+segment_length]

        segments.append({
            "marker": marker,
            "data": segment_data
        })

        # Move to next segment
        pos += 2 + segment_length  # 2 (marker) + segment_length

    return segments

def find_gif_comments(data: bytes) -> list:
    """
    Find comment blocks in a GIF file.

    Args:
        data: GIF file data

    Returns:
        List of comment block data
    """
    if len(data) < 6 or not (data.startswith(b"GIF87a") or data.startswith(b"GIF89a")):
        return []

    comments = []
    pos = 13  # Skip GIF header and logical screen descriptor

    # Skip global color table if present
    if len(data) > 10 and (data[10] & 0x80):
        color_table_size = 2 << (data[10] & 0x07)
        pos += 3 * color_table_size

    while pos < len(data):
        if pos + 2 > len(data):
            break

        block_type = data[pos]

        # Extension block
        if block_type == 0x21:
            if pos + 2 > len(data):
                break

            extension_type = data[pos+1]

            # Comment extension
            if extension_type == 0xFE:
                comment_data = bytearray()
                sub_pos = pos + 2

                while sub_pos < len(data):
                    if sub_pos + 1 > len(data):
                        break

                    block_size = data[sub_pos]

                    if block_size == 0:
                        sub_pos += 1
                        break

                    if sub_pos + 1 + block_size > len(data):
                        break

                    comment_data.extend(data[sub_pos+1:sub_pos+1+block_size])
                    sub_pos += 1 + block_size

                comments.append(bytes(comment_data))
                pos = sub_pos
            else:
                # Skip other extension blocks
                sub_pos = pos + 2

                while sub_pos < len(data):
                    if sub_pos + 1 > len(data):
                        break

                    block_size = data[sub_pos]

                    if block_size == 0:
                        sub_pos += 1
                        break

                    sub_pos += 1 + block_size

                pos = sub_pos

        # Image descriptor
        elif block_type == 0x2C:
            # Skip image descriptor
            pos += 10

            # Skip local color table if present
            if pos < len(data) and (data[pos-1] & 0x80):
                color_table_size = 2 << (data[pos-1] & 0x07)
                pos += 3 * color_table_size

            # Skip image data
            if pos + 1 > len(data):
                break

            pos += 1  # Skip LZW minimum code size

            while pos < len(data):
                if pos + 1 > len(data):
                    break

                block_size = data[pos]

                if block_size == 0:
                    pos += 1
                    break

                pos += 1 + block_size

        # Trailer (end of GIF)
        elif block_type == 0x3B:
            break

        # Unknown block type
        else:
            pos += 1

    return comments

def count_gif_frames(data: bytes) -> int:
    """
    Count the number of frames in a GIF file.

    Args:
        data: GIF file data

    Returns:
        Number of frames
    """
    if len(data) < 6 or not (data.startswith(b"GIF87a") or data.startswith(b"GIF89a")):
        return 0

    frame_count = 0
    pos = 13  # Skip GIF header and logical screen descriptor

    # Skip global color table if present
    if len(data) > 10 and (data[10] & 0x80):
        color_table_size = 2 << (data[10] & 0x07)
        pos += 3 * color_table_size

    while pos < len(data):
        if pos + 1 > len(data):
            break

        block_type = data[pos]

        # Extension block
        if block_type == 0x21:
            if pos + 2 > len(data):
                break

            extension_type = data[pos+1]

            # Skip extension blocks
            sub_pos = pos + 2

            while sub_pos < len(data):
                if sub_pos + 1 > len(data):
                    break

                block_size = data[sub_pos]

                if block_size == 0:
                    sub_pos += 1
                    break

                sub_pos += 1 + block_size

            pos = sub_pos

        # Image descriptor (frame)
        elif block_type == 0x2C:
            frame_count += 1

            # Skip image descriptor
            pos += 10

            # Skip local color table if present
            if pos < len(data) and (data[pos-1] & 0x80):
                color_table_size = 2 << (data[pos-1] & 0x07)
                pos += 3 * color_table_size

            # Skip image data
            if pos + 1 > len(data):
                break

            pos += 1  # Skip LZW minimum code size

            while pos < len(data):
                if pos + 1 > len(data):
                    break

                block_size = data[pos]

                if block_size == 0:
                    pos += 1
                    break

                pos += 1 + block_size

        # Trailer (end of GIF)
        elif block_type == 0x3B:
            break

        # Unknown block type
        else:
            pos += 1

    return frame_count

def find_strings(data: bytes, min_length=4) -> list:
    """
    Find ASCII strings in binary data.

    Args:
        data: Binary data to search
        min_length: Minimum string length to consider

    Returns:
        List of tuples (string, offset)
    """
    result = []
    current_string = ""
    string_start = -1

    for i, byte in enumerate(data):
        if 32 <= byte <= 126:  # ASCII printable character
            if string_start == -1:
                string_start = i
            current_string += chr(byte)
        else:
            if string_start != -1 and len(current_string) >= min_length:
                result.append((current_string, string_start))
            current_string = ""
            string_start = -1

    # Check if we have a string at the end
    if string_start != -1 and len(current_string) >= min_length:
        result.append((current_string, string_start))

    return result

def check_lsb_pattern(pixels) -> bool:
    """
    Check if the least significant bits of pixel values form a pattern.

    Args:
        pixels: List of pixel values

    Returns:
        True if a pattern is detected, False otherwise
    """
    lsbs = []

    # Extract LSBs from pixel channels
    for pixel in pixels:
        # Skip if pixel is not iterable
        if not hasattr(pixel, "__iter__"):
            continue

        # Extract LSB from each channel
        for channel in pixel:
            lsbs.append(channel & 1)

    if len(lsbs) < 100:
        return False

    # Check for patterns in the LSBs
    lsb_groups = [lsbs[i:i+8] for i in range(0, len(lsbs), 8) if i+8 <= len(lsbs)]

    if not lsb_groups:
        return False

    # Convert groups to bytes
    lsb_bytes = []
    for group in lsb_groups:
        byte = 0
        for bit in group:
            byte = (byte << 1) | bit
        lsb_bytes.append(byte)

    # Check if the bytes form a pattern
    return has_pattern(lsb_bytes)

def has_pattern(data) -> bool:
    """
    Check if data has a pattern.

    Args:
        data: List of values to check

    Returns:
        True if a pattern is detected, False otherwise
    """
    if len(data) < 20:
        return False

    # Check if there are significantly fewer unique values than total values
    unique_values = len(set(data))
    if unique_values < len(data) / 3:
        return True

    # Check for repeating sequences
    for length in range(2, 8):
        sequences = {}
        for i in range(len(data) - length):
            seq = tuple(data[i:i+length])
            sequences[seq] = sequences.get(seq, 0) + 1

        # If any sequence repeats more than 3 times, consider it a pattern
        if any(count > 3 for count in sequences.values()):
            return True

    return False

def has_binary_pattern(binary_str: str) -> bool:
    """
    Check if a binary string has a pattern.

    Args:
        binary_str: Binary string to check

    Returns:
        True if a pattern is detected, False otherwise
    """
    if len(binary_str) < 32:
        return False

    # Check if the distribution of 0s and 1s is balanced
    zeros = binary_str.count('0')
    ones = binary_str.count('1')

    # If distribution is very unbalanced, it's likely not random
    if zeros > 0 and ones > 0 and (zeros / ones > 2 or ones / zeros > 2):
        return False

    # Group bits into bytes
    byte_groups = [binary_str[i:i+8] for i in range(0, len(binary_str), 8) if i+8 <= len(binary_str)]

    if not byte_groups:
        return False

    # Convert to integers
    bytes_data = [int(group, 2) for group in byte_groups]

    # Check for patterns in the bytes
    return has_pattern(bytes_data)

def calculate_std_dev(values: list) -> float:
    """
    Calculate standard deviation.

    Args:
        values: List of values

    Returns:
        Standard deviation
    """
    if not values:
        return 0

    mean = sum(values) / len(values)
    variance = sum((x - mean) ** 2 for x in values) / len(values)
    return math.sqrt(variance)

@register_analyzer("opencv_vision_analyzer")
@analyzer_compatibility(requires_binary=True)
def analyze_image_with_opencv(state: State, **kwargs) -> State:
    """
    Analyze image using OpenCV for computer vision tasks.
    This is an alternative to the Anthropic/OpenAI vision API.

    Args:
        state: Current puzzle state
        **kwargs: Additional parameters (ignored)

    Returns:
        Updated state
    """
    if not state.binary_data:
        state.add_insight(
            "No binary image data available for OpenCV analysis",
            analyzer="opencv_vision_analyzer"
        )
        return state

    # Check if OpenCV is available
    if not HAS_OPENCV:
        state.add_insight(
            "OpenCV is not available. Install it with 'pip install opencv-python'",
            analyzer="opencv_vision_analyzer"
        )
        return state

    try:
        # Convert binary data to OpenCV image
        nparr = np.frombuffer(state.binary_data, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

        if img is None:
            state.add_insight(
                "Failed to decode image data with OpenCV",
                analyzer="opencv_vision_analyzer"
            )
            return state

        # Get basic image information
        height, width, channels = img.shape

        state.add_insight(
            f"OpenCV analysis: Image dimensions: {width}x{height}, Channels: {channels}",
            analyzer="opencv_vision_analyzer"
        )

        # Perform various analyses
        results = {}

        # 1. Text detection using OCR (if available)
        try:
            text = detect_text_with_opencv(img)
            if text:
                results["detected_text"] = text
                state.add_insight(
                    f"OpenCV detected text in the image: {text[:100]}{'...' if len(text) > 100 else ''}",
                    analyzer="opencv_vision_analyzer"
                )

                # Add transformation with detected text
                state.add_transformation(
                    name="OpenCV Text Detection",
                    description="Text detected in the image using OpenCV",
                    input_data=f"Image ({width}x{height})",
                    output_data=text,
                    analyzer="opencv_vision_analyzer"
                )
        except Exception as e:
            state.add_insight(
                f"Error in OpenCV text detection: {e}",
                analyzer="opencv_vision_analyzer"
            )

        # 2. Edge detection
        try:
            edges = cv2.Canny(img, 100, 200)
            edge_percentage = np.count_nonzero(edges) / (width * height) * 100
            results["edge_percentage"] = edge_percentage

            state.add_insight(
                f"OpenCV edge detection: {edge_percentage:.2f}% of pixels are edges",
                analyzer="opencv_vision_analyzer"
            )

            # If high edge percentage, might be a diagram or text
            if edge_percentage > 10:
                state.add_insight(
                    "High edge percentage detected, image may contain diagrams, text, or complex patterns",
                    analyzer="opencv_vision_analyzer"
                )
        except Exception as e:
            state.add_insight(
                f"Error in OpenCV edge detection: {e}",
                analyzer="opencv_vision_analyzer"
            )

        # 3. Color analysis
        try:
            # Convert to HSV for better color analysis
            hsv = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)

            # Calculate color histograms
            color_counts = {}

            # Simplified color detection
            color_ranges = {
                "red": ([0, 100, 100], [10, 255, 255]),
                "yellow": ([20, 100, 100], [35, 255, 255]),
                "green": ([36, 100, 100], [70, 255, 255]),
                "blue": ([90, 100, 100], [130, 255, 255]),
                "purple": ([131, 100, 100], [170, 255, 255])
            }

            for color_name, (lower, upper) in color_ranges.items():
                lower = np.array(lower, dtype=np.uint8)
                upper = np.array(upper, dtype=np.uint8)
                mask = cv2.inRange(hsv, lower, upper)
                color_counts[color_name] = np.count_nonzero(mask) / (width * height) * 100

            # Find dominant colors
            dominant_colors = [color for color, percentage in color_counts.items() if percentage > 5]

            if dominant_colors:
                results["dominant_colors"] = dominant_colors
                state.add_insight(
                    f"OpenCV color analysis: Dominant colors: {', '.join(dominant_colors)}",
                    analyzer="opencv_vision_analyzer"
                )
        except Exception as e:
            state.add_insight(
                f"Error in OpenCV color analysis: {e}",
                analyzer="opencv_vision_analyzer"
            )

        # 4. Feature detection
        try:
            # Convert to grayscale for feature detection
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

            # Detect keypoints using FAST algorithm
            fast = cv2.FastFeatureDetector_create()
            keypoints = fast.detect(gray, None)

            results["keypoint_count"] = len(keypoints)
            state.add_insight(
                f"OpenCV feature detection: Found {len(keypoints)} keypoints",
                analyzer="opencv_vision_analyzer"
            )

            # If many keypoints, might be a complex image
            if len(keypoints) > 500:
                state.add_insight(
                    "High number of keypoints detected, image may contain complex patterns or objects",
                    analyzer="opencv_vision_analyzer"
                )
        except Exception as e:
            state.add_insight(
                f"Error in OpenCV feature detection: {e}",
                analyzer="opencv_vision_analyzer"
            )

        # 5. QR code detection
        try:
            qr_data = detect_qr_code(img)
            if qr_data:
                results["qr_code"] = qr_data
                state.add_insight(
                    f"OpenCV detected QR code: {qr_data}",
                    analyzer="opencv_vision_analyzer"
                )

                # Add transformation with QR code data
                state.add_transformation(
                    name="QR Code Detection",
                    description="QR code detected in the image using OpenCV",
                    input_data=f"Image ({width}x{height})",
                    output_data=qr_data,
                    analyzer="opencv_vision_analyzer"
                )
        except Exception as e:
            state.add_insight(
                f"Error in OpenCV QR code detection: {e}",
                analyzer="opencv_vision_analyzer"
            )

        # 6. Check for hidden patterns in bit planes
        try:
            bit_plane_results = analyze_bit_planes(img)
            if bit_plane_results:
                results["bit_plane_analysis"] = bit_plane_results
                state.add_insight(
                    f"OpenCV bit plane analysis: {bit_plane_results}",
                    analyzer="opencv_vision_analyzer"
                )
        except Exception as e:
            state.add_insight(
                f"Error in OpenCV bit plane analysis: {e}",
                analyzer="opencv_vision_analyzer"
            )

        # Add a summary transformation with all results
        if results:
            state.add_transformation(
                name="OpenCV Vision Analysis Summary",
                description="Summary of all OpenCV-based image analyses",
                input_data=f"Image ({width}x{height})",
                output_data=str(results),
                analyzer="opencv_vision_analyzer"
            )

    except Exception as e:
        state.add_insight(
            f"Error in OpenCV image analysis: {e}",
            analyzer="opencv_vision_analyzer"
        )

    return state

def detect_text_with_opencv(img):
    """
    Detect text in an image using OpenCV.
    This is a basic implementation that works without additional dependencies.

    Args:
        img: OpenCV image

    Returns:
        Detected text or empty string if none found
    """
    # Convert to grayscale
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    # Apply thresholding to get binary image
    _, binary = cv2.threshold(gray, 150, 255, cv2.THRESH_BINARY_INV)

    # Find contours
    contours, _ = cv2.findContours(binary, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

    # Filter contours that might be text
    text_contours = []
    for contour in contours:
        x, y, w, h = cv2.boundingRect(contour)
        aspect_ratio = w / float(h)
        area = cv2.contourArea(contour)

        # Text usually has specific aspect ratio and area
        if 0.1 < aspect_ratio < 15 and area > 100:
            text_contours.append(contour)

    # If we found potential text contours, return a message
    if len(text_contours) > 10:
        return f"Detected approximately {len(text_contours)} potential text elements in the image"

    return ""

def detect_qr_code(img):
    """
    Detect QR codes in an image using OpenCV.

    Args:
        img: OpenCV image

    Returns:
        Decoded QR code data or empty string if none found
    """
    # Try to use QRCodeDetector if available (OpenCV 3.4.0+)
    try:
        qr_detector = cv2.QRCodeDetector()
        data, bbox, _ = qr_detector.detectAndDecode(img)

        if data:
            return data
    except:
        pass

    # Fallback method using contour detection
    try:
        # Convert to grayscale
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

        # Apply thresholding
        _, thresh = cv2.threshold(gray, 150, 255, cv2.THRESH_BINARY)

        # Find contours
        contours, _ = cv2.findContours(thresh, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)

        # Look for square contours (potential QR codes)
        for contour in contours:
            # Approximate contour
            peri = cv2.arcLength(contour, True)
            approx = cv2.approxPolyDP(contour, 0.02 * peri, True)

            # If contour has 4 points, it might be a QR code
            if len(approx) == 4:
                x, y, w, h = cv2.boundingRect(contour)
                aspect_ratio = w / float(h)

                # QR codes are square
                if 0.8 < aspect_ratio < 1.2 and w > 30 and h > 30:
                    return "Potential QR code detected (data could not be decoded)"
    except:
        pass

    return ""

def analyze_bit_planes(img):
    """
    Analyze bit planes of an image for hidden patterns.

    Args:
        img: OpenCV image

    Returns:
        Dictionary with analysis results
    """
    results = {}

    # Convert to grayscale
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    # Check each bit plane
    for bit in range(8):
        # Extract bit plane
        bit_plane = (gray >> bit) & 1
        bit_plane = bit_plane * 255  # Scale to 0-255 for visualization

        # Calculate statistics
        non_zero = np.count_nonzero(bit_plane)
        total = bit_plane.size
        percentage = non_zero / total * 100

        # Check for unusual distribution
        if 30 < percentage < 70:
            # Calculate entropy
            hist = cv2.calcHist([bit_plane], [0], None, [2], [0, 256])
            hist = hist / total
            entropy = -np.sum(hist * np.log2(hist + 1e-10))

            # If entropy is high, might contain hidden data
            if entropy > 0.9:
                results[f"bit_plane_{bit}"] = f"Unusual pattern detected (entropy: {entropy:.2f})"

    return results
