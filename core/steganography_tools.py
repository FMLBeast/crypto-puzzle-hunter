"""
Steganography Tools Module

This module provides specialized tools for analyzing and extracting hidden data
from various file types using steganography techniques. It includes tools for
image, audio, text, and binary steganography based on real-world CTF challenges.
"""

import re
import math
import json
import base64
import binascii
import struct
import io
import os
import subprocess
import tempfile
from typing import Dict, List, Any, Optional, Tuple, Union, BinaryIO

# Try to import optional dependencies
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import binwalk
    # Test if binwalk.core is available
    try:
        from binwalk.core.module import Modules
        BINWALK_AVAILABLE = True
    except ImportError:
        # binwalk is installed but missing core module
        try:
            # Try to use our custom binwalk wrapper
            from core.binwalk_wrapper import Modules, scan, ModuleException
            # Monkey patch binwalk module with our scan function
            binwalk.scan = scan
            BINWALK_AVAILABLE = True
            print("Using custom binwalk wrapper as fallback for missing binwalk.core module.")
        except ImportError:
            BINWALK_AVAILABLE = False
            # Print a warning message
            print("Warning: binwalk is installed but binwalk.core module is missing. Using fallback methods.")
except ImportError:
    try:
        # Try to use our custom binwalk wrapper even if binwalk is not installed
        from core.binwalk_wrapper import Modules, scan, ModuleException
        # Create a mock binwalk module
        import types
        binwalk = types.ModuleType('binwalk')
        binwalk.scan = scan
        BINWALK_AVAILABLE = True
        print("Using custom binwalk wrapper as binwalk is not installed.")
    except ImportError:
        BINWALK_AVAILABLE = False

# ---- Image Steganography Tools ----

def extract_image_lsb(data: bytes, bit_plane: int = 0, channels: List[str] = ["r", "g", "b"]) -> Dict[str, Any]:
    """
    Extract least significant bits from image data.

    Args:
        data: Binary image data
        bit_plane: Which bit plane to extract (0 = LSB, 1 = second bit, etc.)
        channels: Which color channels to extract from (r, g, b, a)

    Returns:
        Dictionary with extracted data and analysis
    """
    result = {
        "success": False,
        "extracted_data": None,
        "possible_text": None,
        "possible_encoding": None
    }

    if not PIL_AVAILABLE:
        result["error"] = "PIL library not available. Install with 'pip install pillow'"
        return result

    try:
        # Open image from binary data
        img = Image.open(io.BytesIO(data))
        width, height = img.size

        # Convert to RGB if not already
        if img.mode != "RGB" and img.mode != "RGBA":
            img = img.convert("RGB")

        # Prepare channel mapping
        channel_map = {"r": 0, "g": 1, "b": 2, "a": 3}
        selected_channels = [channel_map[c] for c in channels if c in channel_map]

        # Extract bits
        extracted_bits = []
        pixels = img.load()

        for y in range(height):
            for x in range(width):
                pixel = pixels[x, y]
                for channel in selected_channels:
                    if channel < len(pixel):
                        # Extract the specified bit plane
                        bit = (pixel[channel] >> bit_plane) & 1
                        extracted_bits.append(bit)

        # Convert bits to bytes
        extracted_bytes = bytearray()
        for i in range(0, len(extracted_bits) - 7, 8):
            byte = 0
            for j in range(8):
                if i + j < len(extracted_bits):
                    byte |= extracted_bits[i + j] << (7 - j)
            extracted_bytes.append(byte)

        result["extracted_data"] = bytes(extracted_bytes)

        # Try to interpret as text
        try:
            text = result["extracted_data"].decode('utf-8', errors='ignore')
            result["possible_text"] = text[:1000]  # Limit to first 1000 chars
        except:
            pass

        # Check if it might be encoded data
        try:
            # Check if it's base64
            if re.match(r'^[A-Za-z0-9+/]*={0,2}$', result["possible_text"]):
                decoded = base64.b64decode(result["possible_text"])
                result["possible_encoding"] = "base64"
                result["decoded_data"] = decoded

                # Try to interpret decoded data as text
                try:
                    result["decoded_text"] = decoded.decode('utf-8', errors='ignore')
                except:
                    pass
        except:
            pass

        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result

def extract_appended_data(data: bytes) -> Dict[str, Any]:
    """
    Extract data appended after file EOF markers.

    Args:
        data: Binary file data

    Returns:
        Dictionary with extracted appended data
    """
    result = {
        "success": False,
        "has_appended_data": False,
        "appended_data": None,
        "appended_data_type": "unknown"
    }

    try:
        # Check file signature to determine type
        file_type = "unknown"
        if data[:2] == b'\xff\xd8':
            file_type = "jpeg"
            eof_marker = b'\xff\xd9'
        elif data[:8] == b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a':
            file_type = "png"
            eof_marker = b'\x49\x45\x4e\x44\xae\x42\x60\x82'
        elif data[:3] == b'GIF':
            file_type = "gif"
            eof_marker = b'\x3b'
        elif data[:4] == b'%PDF':
            file_type = "pdf"
            eof_marker = b'%%EOF'
        elif data[:2] == b'BM':
            file_type = "bmp"
            # BMP files don't have a specific EOF marker, but we can use the file size from the header
            if len(data) >= 6:
                # File size is at offset 2, 4 bytes little-endian
                file_size = int.from_bytes(data[2:6], byteorder='little')
                if file_size <= len(data):
                    eof_marker = data[file_size-1:file_size]
                else:
                    result["error"] = "Invalid BMP file size"
                    return result
            else:
                result["error"] = "BMP file too small"
                return result
        else:
            result["error"] = "Unsupported file type"
            return result

        result["file_type"] = file_type

        # Find EOF marker
        if eof_marker in data:
            last_eof_pos = data.rindex(eof_marker) + len(eof_marker)
            if last_eof_pos < len(data):
                appended_data = data[last_eof_pos:]
                result["has_appended_data"] = True
                result["appended_data"] = appended_data
                result["appended_data_size"] = len(appended_data)

                # Try to identify appended data type
                if appended_data.startswith(b'PK'):
                    result["appended_data_type"] = "zip"
                elif appended_data.startswith(b'%PDF'):
                    result["appended_data_type"] = "pdf"
                elif appended_data.startswith(b'\xff\xd8'):
                    result["appended_data_type"] = "jpeg"
                elif appended_data.startswith(b'\x89\x50\x4e\x47'):
                    result["appended_data_type"] = "png"
                elif appended_data.startswith(b'GIF'):
                    result["appended_data_type"] = "gif"
                elif appended_data.startswith(b'ftyp'):
                    result["appended_data_type"] = "mp4"
                elif appended_data.startswith(b'BM'):
                    result["appended_data_type"] = "bmp"

                # Try to interpret as text
                try:
                    text = appended_data.decode('utf-8', errors='ignore')
                    result["appended_text"] = text[:1000]  # Limit to first 1000 chars
                except:
                    pass

        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result

# ---- Audio Steganography Tools ----

def analyze_audio_spectrogram(data: bytes) -> Dict[str, Any]:
    """
    Analyze audio file for hidden data in spectrogram.

    Args:
        data: Binary audio data

    Returns:
        Dictionary with spectrogram analysis
    """
    result = {
        "success": False,
        "has_spectrogram_data": False,
        "spectrogram_data": None
    }

    if not NUMPY_AVAILABLE:
        result["error"] = "NumPy library not available. Install with 'pip install numpy'"
        return result

    try:
        # Check if it's a WAV file
        if data[:4] != b'RIFF' or data[8:12] != b'WAVE':
            result["error"] = "Not a valid WAV file"
            return result

        # Parse WAV header
        channels = struct.unpack_from('<H', data, 22)[0]
        sample_rate = struct.unpack_from('<I', data, 24)[0]
        bits_per_sample = struct.unpack_from('<H', data, 34)[0]

        # Find data chunk
        data_pos = data.find(b'data') + 8
        if data_pos < 8:
            result["error"] = "Could not find data chunk in WAV file"
            return result

        # Extract audio samples
        audio_data = data[data_pos:]
        samples = []

        if bits_per_sample == 8:
            # 8-bit samples are unsigned
            for i in range(0, len(audio_data), channels):
                if i + channels <= len(audio_data):
                    samples.append(audio_data[i] - 128)  # Convert to signed
        elif bits_per_sample == 16:
            # 16-bit samples are signed
            for i in range(0, len(audio_data), 2 * channels):
                if i + 2 <= len(audio_data):
                    sample = struct.unpack_from('<h', audio_data, i)[0]
                    samples.append(sample)

        # Convert to numpy array
        samples = np.array(samples)

        # Perform FFT to get spectrogram data
        # Use a window size appropriate for finding hidden messages
        window_size = 1024
        hop_size = 512

        spectrogram = []
        for i in range(0, len(samples) - window_size, hop_size):
            window = samples[i:i + window_size]
            windowed = window * np.hanning(window_size)
            spectrum = np.abs(np.fft.rfft(windowed))
            spectrogram.append(spectrum)

        # Convert to numpy array
        spectrogram = np.array(spectrogram)

        # Analyze spectrogram for unusual patterns
        # This is a simplified analysis - a real implementation would use image recognition
        # to detect text or patterns in the spectrogram

        # Check for unusual energy distribution
        avg_energy = np.mean(spectrogram)
        max_energy = np.max(spectrogram)
        energy_ratio = max_energy / avg_energy

        result["spectrogram_stats"] = {
            "avg_energy": float(avg_energy),
            "max_energy": float(max_energy),
            "energy_ratio": float(energy_ratio)
        }

        # High energy ratio might indicate hidden data
        if energy_ratio > 100:
            result["has_spectrogram_data"] = True

        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result

# ---- Text Steganography Tools ----

def analyze_zero_width_chars(text: str) -> Dict[str, Any]:
    """
    Analyze text for zero-width characters that might hide data.

    Args:
        text: Text to analyze

    Returns:
        Dictionary with analysis results
    """
    result = {
        "success": False,
        "has_zero_width_chars": False,
        "zero_width_chars": [],
        "extracted_bits": [],
        "extracted_text": None
    }

    try:
        # Define zero-width characters
        zero_width_chars = {
            '\u200b': 'ZWSP',  # Zero-Width Space
            '\u200c': 'ZWNJ',  # Zero-Width Non-Joiner
            '\u200d': 'ZWJ',   # Zero-Width Joiner
            '\u2060': 'WJ',    # Word Joiner
            '\u2061': 'FA',    # Function Application
            '\u2062': 'IT',    # Invisible Times
            '\u2063': 'IS',    # Invisible Separator
            '\u2064': 'IP',    # Invisible Plus
            '\ufeff': 'BOM'    # Byte Order Mark
        }

        # Find zero-width characters
        found_chars = []
        for i, char in enumerate(text):
            if char in zero_width_chars:
                found_chars.append({
                    'position': i,
                    'char': char,
                    'name': zero_width_chars[char]
                })

        if found_chars:
            result["has_zero_width_chars"] = True
            result["zero_width_chars"] = found_chars

            # Extract bits (assuming ZWNJ=0, ZWJ=1 encoding)
            bits = []
            for char_info in found_chars:
                if char_info['char'] == '\u200c':  # ZWNJ
                    bits.append(0)
                elif char_info['char'] == '\u200d':  # ZWJ
                    bits.append(1)

            result["extracted_bits"] = bits

            # Convert bits to bytes
            if bits:
                extracted_bytes = bytearray()
                for i in range(0, len(bits) - 7, 8):
                    byte = 0
                    for j in range(8):
                        if i + j < len(bits):
                            byte |= bits[i + j] << (7 - j)
                    extracted_bytes.append(byte)

                # Try to interpret as text
                try:
                    extracted_text = extracted_bytes.decode('utf-8', errors='ignore')
                    result["extracted_text"] = extracted_text
                except:
                    pass

        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result

def extract_first_letters(text: str) -> Dict[str, Any]:
    """
    Extract first letters from lines or paragraphs to find hidden messages.

    Args:
        text: Text to analyze

    Returns:
        Dictionary with extracted messages
    """
    result = {
        "success": False,
        "first_letters_line": "",
        "first_letters_paragraph": "",
        "first_words": []
    }

    try:
        # Split into lines and paragraphs
        lines = [line.strip() for line in text.split('\n') if line.strip()]
        paragraphs = [para.strip() for para in text.split('\n\n') if para.strip()]

        # Extract first letters from lines
        first_letters_line = ''.join(line[0] for line in lines if line)
        result["first_letters_line"] = first_letters_line

        # Extract first letters from paragraphs
        first_letters_para = ''.join(para[0] for para in paragraphs if para)
        result["first_letters_paragraph"] = first_letters_para

        # Extract first words
        first_words = [line.split()[0] if line.split() else '' for line in lines]
        result["first_words"] = first_words

        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result

# ---- Binary Analysis Tools ----

def find_embedded_files(data: bytes) -> Dict[str, Any]:
    """
    Find embedded files within binary data.

    Args:
        data: Binary data to analyze

    Returns:
        Dictionary with found file signatures
    """
    result = {
        "success": False,
        "embedded_files": []
    }

    try:
        # Define common file signatures
        signatures = {
            b'\xff\xd8\xff': "jpeg",
            b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a': "png",
            b'GIF8': "gif",
            b'%PDF': "pdf",
            b'PK\x03\x04': "zip",
            b'Rar!\x1a\x07': "rar",
            b'7z\xbc\xaf\x27\x1c': "7z",
            b'\x1f\x8b': "gzip",
            b'BZh': "bzip2",
            b'ftyp': "mp4",
            b'ID3': "mp3",
            b'OggS': "ogg",
            b'RIFF': "wav or avi",
            b'\x00\x00\x01\xba': "mpeg",
            b'\x00\x00\x01\xb3': "mpeg",
            b'BM': "bmp"
        }

        # Search for file signatures
        for signature, file_type in signatures.items():
            pos = 0
            while True:
                pos = data.find(signature, pos)
                if pos == -1:
                    break

                result["embedded_files"].append({
                    "offset": pos,
                    "signature": signature.hex(),
                    "file_type": file_type
                })

                pos += 1

        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result

# ---- External Tool Integration ----

def run_zsteg(data: bytes) -> Dict[str, Any]:
    """
    Run zsteg on image data to detect steganography.

    Args:
        data: Binary image data

    Returns:
        Dictionary with zsteg analysis results
    """
    result = {
        "success": False,
        "tool": "zsteg",
        "findings": []
    }

    try:
        # Check if the data is a PNG or BMP (zsteg only works with these formats)
        is_png = data[:8] == b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a'
        is_bmp = data[:2] == b'BM'

        if not (is_png or is_bmp):
            result["error"] = "zsteg only works with PNG and BMP files"
            return result

        # Create a temporary file to store the image
        with tempfile.NamedTemporaryFile(delete=False, suffix='.png' if is_png else '.bmp') as temp_file:
            temp_file.write(data)
            temp_path = temp_file.name

        try:
            # Run zsteg command
            cmd = ["zsteg", temp_path]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate(timeout=30)

            if process.returncode != 0:
                result["error"] = f"zsteg failed with error: {stderr.decode('utf-8', errors='ignore')}"
                return result

            # Parse zsteg output
            output = stdout.decode('utf-8', errors='ignore')
            lines = output.split('\n')

            for line in lines:
                if line.strip():
                    # Parse the line to extract information
                    if ":" in line:
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            key = parts[0].strip()
                            value = parts[1].strip()
                            result["findings"].append({
                                "type": key,
                                "content": value
                            })

            result["success"] = True
            result["raw_output"] = output

        finally:
            # Clean up the temporary file
            try:
                os.unlink(temp_path)
            except:
                pass

    except FileNotFoundError:
        result["error"] = "zsteg command not found. Install with: gem install zsteg"
    except Exception as e:
        result["error"] = f"Error running zsteg: {str(e)}"

    return result

def run_binwalk(data: bytes) -> Dict[str, Any]:
    """
    Run binwalk on binary data to find embedded files and signatures.

    Args:
        data: Binary data to analyze

    Returns:
        Dictionary with binwalk analysis results
    """
    result = {
        "success": False,
        "tool": "binwalk",
        "signatures": [],
        "extracted_files": []
    }

    # First try to use the Python binwalk module if available
    if BINWALK_AVAILABLE:
        try:
            # Create a temporary directory for extraction
            with tempfile.TemporaryDirectory() as temp_dir:
                # Create a temporary file for the binary data
                with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                    temp_file.write(data)
                    temp_path = temp_file.name

                try:
                    # Verify that binwalk.core is available by trying to access a method
                    # This is an additional check to ensure we don't get ModuleNotFoundError
                    if not hasattr(binwalk, 'scan'):
                        raise ModuleNotFoundError("binwalk.scan method not available")

                    # Run signature scan
                    signature_results = binwalk.scan(temp_path, signature=True, quiet=True)

                    # Process signature results
                    for module in signature_results:
                        for entry in module.results:
                            result["signatures"].append({
                                "offset": entry.offset,
                                "description": entry.description
                            })

                    # Run extraction
                    extraction_results = binwalk.scan(temp_path, extract=True, quiet=True, directory=temp_dir)

                    # Check if any files were extracted
                    extracted_dir = os.path.join(temp_dir, "_" + os.path.basename(temp_path) + ".extracted")
                    if os.path.exists(extracted_dir):
                        for root, dirs, files in os.walk(extracted_dir):
                            for file in files:
                                file_path = os.path.join(root, file)
                                rel_path = os.path.relpath(file_path, extracted_dir)

                                # Read the extracted file
                                with open(file_path, 'rb') as f:
                                    file_data = f.read()

                                result["extracted_files"].append({
                                    "name": rel_path,
                                    "size": len(file_data),
                                    "data": file_data  # Store the full data
                                })

                    result["success"] = True

                finally:
                    # Clean up the temporary file
                    try:
                        os.unlink(temp_path)
                    except:
                        pass

        except ModuleNotFoundError as e:
            # Specific handling for missing modules
            result["error"] = f"Missing binwalk module: {str(e)}"
            result["fallback"] = "Falling back to command-line binwalk"
        except AttributeError as e:
            # Handle the case where binwalk is installed but missing required attributes
            result["error"] = f"Incomplete binwalk installation: {str(e)}"
            result["fallback"] = "Falling back to command-line binwalk"
        except Exception as e:
            result["error"] = f"Error using binwalk module: {str(e)}"
            result["fallback"] = "Falling back to command-line binwalk"

    # If Python module failed or is not available, try command-line binwalk
    if not result["success"]:
        try:
            # Create a temporary directory for extraction
            with tempfile.TemporaryDirectory() as temp_dir:
                # Create a temporary file for the binary data
                with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                    temp_file.write(data)
                    temp_path = temp_file.name

                try:
                    # First check if binwalk command is available
                    try:
                        subprocess.run(["binwalk", "--help"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=5)
                    except (FileNotFoundError, subprocess.SubprocessError):
                        # Use our own file signature detection if binwalk is not available
                        result["error"] = "binwalk command not available, using built-in signature detection"
                        embedded_files = find_embedded_files(data)
                        if embedded_files["success"] and embedded_files["embedded_files"]:
                            for file_info in embedded_files["embedded_files"]:
                                result["signatures"].append({
                                    "offset": file_info["offset"],
                                    "description": f"{file_info['file_type']} signature"
                                })
                            result["success"] = True
                        return result

                    # Run binwalk signature scan
                    cmd = ["binwalk", temp_path]
                    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = process.communicate(timeout=30)

                    if process.returncode != 0:
                        result["error"] = f"binwalk failed with error: {stderr.decode('utf-8', errors='ignore')}"
                    else:
                        # Parse binwalk output
                        output = stdout.decode('utf-8', errors='ignore')
                        lines = output.split('\n')

                        for line in lines:
                            if line.strip() and not line.startswith("DECIMAL") and not line.startswith("-"):
                                parts = line.split(None, 2)
                                if len(parts) >= 3:
                                    try:
                                        offset = int(parts[0])
                                        description = parts[2]
                                        result["signatures"].append({
                                            "offset": offset,
                                            "description": description
                                        })
                                    except:
                                        pass

                        # Run binwalk extraction
                        cmd = ["binwalk", "-e", "-C", temp_dir, temp_path]
                        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        stdout, stderr = process.communicate(timeout=30)

                        # Check if any files were extracted
                        extracted_dir = os.path.join(temp_dir, "_" + os.path.basename(temp_path) + ".extracted")
                        if os.path.exists(extracted_dir):
                            for root, dirs, files in os.walk(extracted_dir):
                                for file in files:
                                    file_path = os.path.join(root, file)
                                    rel_path = os.path.relpath(file_path, extracted_dir)

                                    # Read the extracted file
                                    with open(file_path, 'rb') as f:
                                        file_data = f.read()

                                    result["extracted_files"].append({
                                        "name": rel_path,
                                        "size": len(file_data),
                                        "data": file_data  # Store the full data
                                    })

                        result["success"] = True
                        result["raw_output"] = output

                finally:
                    # Clean up the temporary file
                    try:
                        os.unlink(temp_path)
                    except:
                        pass

        except FileNotFoundError:
            result["error"] = "binwalk command not found. Using built-in signature detection."
            # Use our own file signature detection as a last resort
            embedded_files = find_embedded_files(data)
            if embedded_files["success"] and embedded_files["embedded_files"]:
                for file_info in embedded_files["embedded_files"]:
                    result["signatures"].append({
                        "offset": file_info["offset"],
                        "description": f"{file_info['file_type']} signature"
                    })
                result["success"] = True
        except Exception as e:
            result["error"] = f"Error running binwalk: {str(e)}"

    return result

# ---- Main Steganography Analysis Function ----

def analyze_stego(data: bytes, file_type: str = None) -> Dict[str, Any]:
    """
    Comprehensive steganography analysis for various file types.

    Args:
        data: Binary data to analyze
        file_type: Optional file type hint

    Returns:
        Dictionary with analysis results
    """
    result = {
        "success": False,
        "file_type": file_type,
        "analysis_results": {}
    }

    try:
        # Determine file type if not provided
        if not file_type:
            # Check file signature
            if data[:2] == b'\xff\xd8':
                file_type = "jpeg"
            elif data[:8] == b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a':
                file_type = "png"
            elif data[:3] == b'GIF':
                file_type = "gif"
            elif data[:4] == b'%PDF':
                file_type = "pdf"
            elif data[:2] == b'PK':
                file_type = "zip"
            elif data[:4] == b'Rar!':
                file_type = "rar"
            elif data[:4] == b'RIFF' and data[8:12] == b'WAVE':
                file_type = "wav"
            elif data[:3] == b'ID3' or data[:2] == b'\xff\xfb':
                file_type = "mp3"
            elif data[:4] == b'ftyp':
                file_type = "mp4"
            elif data[:2] == b'BM':
                file_type = "bmp"
            else:
                # Try to detect text
                try:
                    text = data.decode('utf-8', errors='ignore')
                    if text.isprintable():
                        file_type = "text"
                except:
                    file_type = "unknown"

        result["file_type"] = file_type

        # Apply appropriate analysis based on file type
        if file_type in ["jpeg", "png", "gif", "bmp"]:
            # Image steganography analysis
            result["analysis_results"]["lsb"] = extract_image_lsb(data)
            result["analysis_results"]["appended_data"] = extract_appended_data(data)
            result["analysis_results"]["embedded_files"] = find_embedded_files(data)

            # Run zsteg on PNG and BMP files
            if file_type in ["png", "bmp"]:
                result["analysis_results"]["zsteg"] = run_zsteg(data)

            # Run binwalk on all image types
            result["analysis_results"]["binwalk"] = run_binwalk(data)

        elif file_type in ["wav", "mp3"]:
            # Audio steganography analysis
            if file_type == "wav":
                result["analysis_results"]["spectrogram"] = analyze_audio_spectrogram(data)

            result["analysis_results"]["embedded_files"] = find_embedded_files(data)

            # Run binwalk on audio files
            result["analysis_results"]["binwalk"] = run_binwalk(data)

        elif file_type == "text":
            # Text steganography analysis
            text = data.decode('utf-8', errors='ignore')
            result["analysis_results"]["zero_width"] = analyze_zero_width_chars(text)
            result["analysis_results"]["first_letters"] = extract_first_letters(text)

        else:
            # Generic binary analysis
            result["analysis_results"]["embedded_files"] = find_embedded_files(data)

            # Run binwalk on all binary files
            result["analysis_results"]["binwalk"] = run_binwalk(data)

        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result
