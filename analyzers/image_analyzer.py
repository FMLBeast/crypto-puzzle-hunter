"""
Enhanced Image Analyzer with Advanced Steganography Capabilities
Integrates sophisticated steganography extraction techniques into Crypto Hunter
"""

import io
import re
import math
import zlib
import struct
import binascii
import itertools
from typing import List, Tuple, Optional, Dict, Any, Union, Callable
from core.state import State
from analyzers.base import register_analyzer, analyzer_compatibility

# Optional dependencies
try:
    from PIL import Image, ExifTags, PngImagePlugin
    import numpy as np

    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    import cv2

    HAS_OPENCV = True
except ImportError:
    HAS_OPENCV = False


class AdvancedSteganographyExtractor:
    """Advanced steganography extraction capabilities for Crypto Hunter"""

    def __init__(self, image_data: bytes, verbose: bool = False):
        self.image_data = image_data
        self.verbose = verbose
        self.results = {}
        self.result_hashes = set()

        if HAS_PIL:
            try:
                self.image = Image.open(io.BytesIO(image_data))
                self.pixels_pil = np.array(self.image)
                self.width, self.height = self.image.size
            except Exception:
                self.image = None
                self.pixels_pil = None
                self.width = self.height = 0
        else:
            self.image = None
            self.pixels_pil = None
            self.width = self.height = 0

        if HAS_OPENCV:
            try:
                # Convert bytes to numpy array for OpenCV
                nparr = np.frombuffer(image_data, np.uint8)
                self.pixels_cv2 = cv2.imdecode(nparr, cv2.IMREAD_UNCHANGED)
            except Exception:
                self.pixels_cv2 = None
        else:
            self.pixels_cv2 = None

    def extract_multi_bitplane_advanced(self) -> Dict[str, bytes]:
        """Extract data from multiple bit planes with advanced configurations"""
        results = {}

        if not HAS_PIL or self.pixels_pil is None:
            return results

        # Check available channels
        if len(self.pixels_pil.shape) < 3:
            available_channels = [0]  # Grayscale
        else:
            available_channels = list(range(min(4, self.pixels_pil.shape[2])))

        channel_names = ['r', 'g', 'b', 'a']

        # Try different bitplanes (b1-b8 where b1 is LSB)
        for bit_plane in range(8):
            for channel in available_channels:
                if channel == 3 and len(self.pixels_pil.shape) < 4:
                    continue

                # Advanced bit orderings and scan patterns
                for bit_order in ['lsb', 'msb']:
                    for scan_order in ['xy', 'yx', 'spiral', 'zigzag']:
                        bits = self._extract_bits_advanced(
                            bit_plane, channel, bit_order, scan_order
                        )

                        if bits:
                            data = self._bits_to_bytes(bits)
                            if self._is_meaningful_data(data):
                                bp_name = f"b{bit_plane + 1}"
                                ch_name = channel_names[channel] if channel < 4 else f"ch{channel}"
                                key = f"{bp_name}_{ch_name}_{bit_order}_{scan_order}"
                                results[key] = data

        return results

    def extract_prime_fibonacci_patterns(self) -> Dict[str, bytes]:
        """Extract data using prime and Fibonacci pixel indexing"""
        results = {}

        if not HAS_PIL or self.pixels_pil is None:
            return results

        # Try prime and Fibonacci filters
        for filter_type in ['prime', 'fibonacci']:
            for bit_plane in [0, 2, 4]:
                for channel in range(min(4, self.pixels_pil.shape[2] if len(self.pixels_pil.shape) > 2 else 1)):
                    filter_func = self._get_special_filter(filter_type)

                    bits = self._extract_bits_advanced(
                        bit_plane, channel, 'lsb', 'xy', filter_func
                    )

                    if bits:
                        data = self._bits_to_bytes(bits)
                        if self._is_meaningful_data(data):
                            ch_name = ['r', 'g', 'b', 'a'][channel] if channel < 4 else f"ch{channel}"
                            key = f"b{bit_plane + 1}_{ch_name}_{filter_type}"
                            results[key] = data

        return results

    def extract_xor_patterns(self) -> Dict[str, bytes]:
        """Extract data with XOR pattern analysis"""
        results = {}

        if not HAS_PIL or self.pixels_pil is None:
            return results

        xor_keys = [
            bytes([0xFF]), bytes([0x55]), bytes([0xAA]), bytes([0x33]),
            b'key', b'password', bytes(range(16))
        ]

        for bit_plane in [0, 2, 4]:
            for channel in range(min(4, self.pixels_pil.shape[2] if len(self.pixels_pil.shape) > 2 else 1)):
                bits = self._extract_bits_advanced(bit_plane, channel, 'lsb', 'xy')

                if bits:
                    raw_data = self._bits_to_bytes(bits)

                    for key in xor_keys:
                        xor_data = bytearray()
                        for i, b in enumerate(raw_data):
                            xor_data.append(b ^ key[i % len(key)])

                        if self._is_meaningful_data(bytes(xor_data)):
                            ch_name = ['r', 'g', 'b', 'a'][channel] if channel < 4 else f"ch{channel}"
                            key_desc = binascii.hexlify(key[:4]).decode('ascii')
                            key_name = f"b{bit_plane + 1}_{ch_name}_xor_{key_desc}"
                            results[key_name] = bytes(xor_data)

        return results

    def extract_frequency_domain(self) -> Dict[str, bytes]:
        """Extract data from DCT/DFT frequency domain"""
        results = {}

        if not HAS_OPENCV or self.pixels_cv2 is None:
            return results

        channels = min(3, self.pixels_cv2.shape[2] if len(self.pixels_cv2.shape) > 2 else 1)

        for channel in range(channels):
            if channels > 1:
                channel_data = self.pixels_cv2[:, :, channel]
            else:
                channel_data = self.pixels_cv2

            # DCT analysis
            try:
                dct_data = cv2.dct(np.float32(channel_data))

                # Extract from different frequency regions
                for region, (start_y, end_y, start_x, end_x) in [
                    ('low', (0, 8, 0, 8)),
                    ('mid', (8, 24, 8, 24)),
                    ('high', (24, 32, 24, 32))
                ]:
                    bits = []
                    for y in range(start_y, min(end_y, dct_data.shape[0])):
                        for x in range(start_x, min(end_x, dct_data.shape[1])):
                            coef = int(dct_data[y, x])
                            bits.append(coef & 1)

                    if bits:
                        data = self._bits_to_bytes(bits)
                        if self._is_meaningful_data(data):
                            ch_name = ['r', 'g', 'b'][channel] if channel < 3 else f"ch{channel}"
                            key = f"dct_{ch_name}_{region}_freq"
                            results[key] = data

            except Exception:
                pass

            # DFT analysis
            try:
                dft_data = cv2.dft(np.float32(channel_data), flags=cv2.DFT_COMPLEX_OUTPUT)
                magnitude, phase = cv2.cartToPolar(dft_data[:, :, 0], dft_data[:, :, 1])

                # Extract from magnitude and phase
                for domain, data_source in [('magnitude', magnitude), ('phase', phase)]:
                    bits = []
                    for y in range(min(16, data_source.shape[0])):
                        for x in range(min(16, data_source.shape[1])):
                            val = int(data_source[y, x] * (100 if domain == 'phase' else 1))
                            bits.append(val & 1)

                    if bits:
                        data = self._bits_to_bytes(bits)
                        if self._is_meaningful_data(data):
                            ch_name = ['r', 'g', 'b'][channel] if channel < 3 else f"ch{channel}"
                            key = f"dft_{ch_name}_{domain}"
                            results[key] = data

            except Exception:
                pass

        return results

    def extract_png_chunks_advanced(self) -> Dict[str, bytes]:
        """Advanced PNG chunk analysis"""
        results = {}

        if not self.image_data.startswith(b'\x89PNG\r\n\x1a\n'):
            return results

        data = self.image_data[8:]  # Skip PNG signature
        chunks = {}
        hidden_chunks = {}

        while data and len(data) >= 8:
            try:
                length = struct.unpack('>I', data[:4])[0]
                if len(data) < length + 12:
                    break

                chunk_type = data[4:8].decode('latin-1', errors='ignore')
                chunk_data = data[8:8 + length]

                # Store chunks
                if chunk_type in chunks:
                    if not isinstance(chunks[chunk_type], list):
                        chunks[chunk_type] = [chunks[chunk_type]]
                    chunks[chunk_type].append(chunk_data)
                else:
                    chunks[chunk_type] = chunk_data

                # Identify hidden/ancillary chunks
                if chunk_type[0].islower() and chunk_type not in ['tEXt', 'zTXt', 'iTXt']:
                    hidden_chunks[chunk_type] = chunk_data

                data = data[12 + length:]
            except Exception:
                break

        # Process non-standard chunks
        standard_chunks = {'IDAT', 'IHDR', 'IEND', 'PLTE', 'cHRM', 'gAMA', 'sBIT', 'sRGB', 'bKGD', 'hIST', 'tRNS',
                           'pHYs'}

        for chunk_type, chunk_data in chunks.items():
            if chunk_type not in standard_chunks:
                if isinstance(chunk_data, list):
                    for i, data in enumerate(chunk_data):
                        results[f"chunk_{chunk_type}_{i}"] = data
                        # Try decompression
                        try:
                            decompressed = zlib.decompress(data)
                            results[f"chunk_{chunk_type}_{i}_decompressed"] = decompressed
                        except:
                            pass
                else:
                    results[f"chunk_{chunk_type}"] = chunk_data
                    try:
                        decompressed = zlib.decompress(chunk_data)
                        results[f"chunk_{chunk_type}_decompressed"] = decompressed
                    except:
                        pass

        # Process hidden chunks
        for chunk_type, chunk_data in hidden_chunks.items():
            results[f"hidden_chunk_{chunk_type}"] = chunk_data
            try:
                decompressed = zlib.decompress(chunk_data)
                results[f"hidden_chunk_{chunk_type}_decompressed"] = decompressed
            except:
                pass

        return results

    def _extract_bits_advanced(self, bit_plane: int, channel: int, bit_order: str = 'lsb',
                               scan_order: str = 'xy', filter_func: Optional[Callable] = None) -> List[int]:
        """Advanced bit extraction with multiple parameters"""
        if not HAS_PIL or self.pixels_pil is None:
            return []

        # Calculate bit position
        if bit_order.lower() == 'lsb':
            bit_pos = bit_plane
        else:  # msb
            bit_pos = 7 - bit_plane

        # Get image dimensions
        if len(self.pixels_pil.shape) == 3:
            height, width, _ = self.pixels_pil.shape
        else:
            height, width = self.pixels_pil.shape

        # Generate coordinates based on scan order
        coords = self._get_scan_coordinates(width, height, scan_order)

        # Apply filter if provided
        if filter_func:
            coords = [(x, y) for x, y in coords if filter_func(x, y)]

        # Extract bits
        bits = []
        for x, y in coords:
            try:
                if len(self.pixels_pil.shape) == 3 and channel < self.pixels_pil.shape[2]:
                    pixel_value = self.pixels_pil[y, x, channel]
                    bits.append((pixel_value >> bit_pos) & 1)
                elif len(self.pixels_pil.shape) == 2 and channel == 0:
                    pixel_value = self.pixels_pil[y, x]
                    bits.append((pixel_value >> bit_pos) & 1)
            except IndexError:
                continue

        return bits

    def _get_scan_coordinates(self, width: int, height: int, scan_order: str) -> List[Tuple[int, int]]:
        """Generate pixel coordinates based on scan order"""
        if scan_order == 'xy':
            return [(x, y) for y in range(height) for x in range(width)]
        elif scan_order == 'yx':
            return [(x, y) for x in range(width) for y in range(height)]
        elif scan_order == 'spiral':
            return self._spiral_coordinates(width, height)
        elif scan_order == 'zigzag':
            return self._zigzag_coordinates(width, height)
        else:
            return [(x, y) for y in range(height) for x in range(width)]

    def _spiral_coordinates(self, width: int, height: int) -> List[Tuple[int, int]]:
        """Generate coordinates in spiral pattern"""
        coords = []
        x, y = width // 2, height // 2
        dx, dy = 0, -1

        for i in range(max(width, height) ** 2):
            if (-width // 2 < x <= width // 2) and (-height // 2 < y <= height // 2):
                adj_x, adj_y = x + width // 2, y + height // 2
                if 0 <= adj_x < width and 0 <= adj_y < height:
                    coords.append((adj_x, adj_y))

            if x == y or (x < 0 and x == -y) or (x > 0 and x == 1 - y):
                dx, dy = -dy, dx

            x, y = x + dx, y + dy

            if len(coords) >= width * height:
                break

        return coords

    def _zigzag_coordinates(self, width: int, height: int) -> List[Tuple[int, int]]:
        """Generate coordinates in zigzag pattern"""
        coords = []

        for sum_idx in range(width + height - 1):
            if sum_idx % 2 == 0:
                for x in range(min(sum_idx, width - 1), max(0, sum_idx - height + 1) - 1, -1):
                    y = sum_idx - x
                    if 0 <= y < height:
                        coords.append((x, y))
            else:
                for x in range(max(0, sum_idx - height + 1), min(sum_idx, width - 1) + 1):
                    y = sum_idx - x
                    if 0 <= y < height:
                        coords.append((x, y))

        return coords

    def _get_special_filter(self, filter_type: str) -> Callable:
        """Get special pixel filter function"""
        if filter_type == 'prime':
            return lambda x, y: self._is_prime(y * self.width + x if self.width else 0)
        elif filter_type == 'fibonacci':
            return lambda x, y: self._is_fibonacci(y * self.width + x if self.width else 0)
        else:
            return lambda x, y: True

    def _is_prime(self, n: int) -> bool:
        """Check if number is prime"""
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0 or n % 3 == 0:
            return False
        i = 5
        while i * i <= n:
            if n % i == 0 or n % (i + 2) == 0:
                return False
            i += 6
        return True

    def _is_fibonacci(self, n: int) -> bool:
        """Check if number is Fibonacci"""

        def is_perfect_square(num):
            if num < 0:
                return False
            sqrt = int(num ** 0.5)
            return sqrt * sqrt == num

        return is_perfect_square(5 * n * n + 4) or is_perfect_square(5 * n * n - 4)

    def _bits_to_bytes(self, bits: List[int]) -> bytes:
        """Convert list of bits to bytes"""
        if not bits:
            return b''

        while len(bits) % 8 != 0:
            bits.append(0)

        result = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                if i + j < len(bits):
                    byte |= (bits[i + j] << (7 - j))
            result.append(byte)

        return bytes(result)

    def _is_meaningful_data(self, data: bytes) -> bool:
        """Check if extracted data appears meaningful"""
        if not data or len(data) < 4:
            return False

        # Check if it's not all zeros or all 255s
        if all(b == 0 for b in data) or all(b == 255 for b in data):
            return False

        # Check for repetitive patterns
        if len(set(data)) == 1:
            return False

        # Check entropy (basic)
        unique_bytes = len(set(data))
        if unique_bytes < len(data) / 10:  # Very low entropy
            return False

        # Check for ASCII text patterns
        try:
            text = data.decode('utf-8', errors='ignore')
            if any(word in text.lower() for word in ['flag', 'key', 'secret', 'password', 'message', 'ctf']):
                return True
        except:
            pass

        # Check for common file signatures
        if _detect_file_type(data):
            return True

        return True


def _detect_file_type(data: bytes) -> Optional[str]:
    """Detect file type from binary data"""
    if len(data) < 8:
        return None

    signatures = {
        b'\xFF\xD8\xFF': 'JPEG image',
        b'\x89PNG\r\n\x1A\n': 'PNG image',
        b'GIF8': 'GIF image',
        b'\x25\x50\x44\x46': 'PDF document',
        b'PK\x03\x04': 'ZIP archive',
        b'\x52\x61\x72\x21': 'RAR archive',
        b'7z\xBC\xAF\x27\x1C': '7z archive',
        b'\x1F\x8B': 'GZIP archive',
        b'BM': 'BMP image',
        b'RIFF': 'WAV/AVI file',
        b'ID3': 'MP3 audio',
    }

    for sig, file_type in signatures.items():
        if data.startswith(sig):
            return file_type

    return None


def find_strings(data: bytes, min_length: int = 4) -> List[Tuple[str, int]]:
    """Find ASCII strings in binary data"""
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


@register_analyzer("advanced_steganography")
@register_analyzer("steganography_analyzer")
@register_analyzer("steganography_extractor")
@register_analyzer("image_analyzer")
@analyzer_compatibility(requires_binary=True)
def analyze_image(state: State, **kwargs) -> State:
    """
    Comprehensive image analysis with advanced steganography extraction
    """
    if not state.binary_data:
        return state

    # Detect image type via header
    header = state.binary_data[:8]
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        state.file_type = "png"
    elif header.startswith(b"\xff\xd8"):
        state.file_type = "jpeg"
    elif header.startswith(b"GIF87a") or header.startswith(b"GIF89a"):
        state.file_type = "gif"
    elif header.startswith(b"BM"):
        state.file_type = "bmp"
    else:
        state.add_insight("Unsupported or non-image file", analyzer="image_analyzer")
        return state

    state.add_insight(f"Analyzing {state.file_type.upper()} image ({state.file_size} bytes)", analyzer="image_analyzer")

    # Basic image analysis with PIL
    if HAS_PIL:
        analyze_with_pil(state)
    else:
        state.add_insight("PIL not available; limited analysis", analyzer="image_analyzer")

    # Text extraction from raw bytes
    extract_text_from_image(state)

    # Basic LSB steganography checks
    check_basic_lsb_steganography(state)

    # Embedded file detection
    check_embedded_files(state)

    # Advanced steganography analysis
    try:
        state.add_insight(f"Starting advanced steganography analysis", analyzer="image_analyzer")

        extractor = AdvancedSteganographyExtractor(state.binary_data, verbose=False)

        # Run advanced extractions
        results = {}

        # Multi-bitplane analysis
        state.add_insight("Performing multi-bitplane analysis with advanced scan patterns", analyzer="image_analyzer")
        results.update(extractor.extract_multi_bitplane_advanced())

        # Prime/Fibonacci pattern analysis
        state.add_insight("Analyzing prime and Fibonacci pixel patterns", analyzer="image_analyzer")
        results.update(extractor.extract_prime_fibonacci_patterns())

        # XOR pattern analysis
        state.add_insight("Testing XOR obfuscation patterns", analyzer="image_analyzer")
        results.update(extractor.extract_xor_patterns())

        # Frequency domain analysis
        if HAS_OPENCV:
            state.add_insight("Analyzing frequency domain (DCT/DFT)", analyzer="image_analyzer")
            results.update(extractor.extract_frequency_domain())

        # PNG chunk analysis
        if state.file_type == "png":
            state.add_insight("Performing comprehensive PNG chunk analysis", analyzer="image_analyzer")
            results.update(extractor.extract_png_chunks_advanced())

        # Process results
        high_confidence_results = []
        meaningful_results = []

        for method, data in results.items():
            if len(data) >= 16:  # Minimum meaningful size

                # Try to decode as text
                try:
                    text = data.decode('utf-8', errors='ignore')
                    # Check if it contains readable text or keywords
                    if any(word in text.lower() for word in ['flag', 'key', 'secret', 'password', 'message', 'ctf']):
                        high_confidence_results.append((method, text))
                        state.add_insight(f"High-confidence extraction via {method}: potential message found",
                                          analyzer="image_analyzer")

                        state.add_transformation(
                            name=f"Advanced Steganography - {method}",
                            description=f"Extracted hidden text using {method}",
                            input_data=f"Image analysis via {method}",
                            output_data=text,
                            analyzer="image_analyzer"
                        )

                        # Set as puzzle text if it looks like a solution
                        if not state.puzzle_text and len(text.strip()) > 10:
                            state.set_puzzle_text(text.strip())

                        continue
                    elif len([c for c in text if c.isprintable()]) > len(text) * 0.7:
                        # Mostly printable text
                        meaningful_results.append((method, text))
                except:
                    pass

                # Check for common file signatures
                file_type = _detect_file_type(data)
                if file_type:
                    state.add_insight(f"Extracted {file_type} via {method} ({len(data)} bytes)",
                                      analyzer="image_analyzer")

                    state.add_transformation(
                        name=f"Advanced Steganography - {method}",
                        description=f"Extracted {file_type} using {method}",
                        input_data=f"Image analysis via {method}",
                        output_data=f"Binary data ({len(data)} bytes): {data[:100].hex()}{'...' if len(data) > 100 else ''}",
                        analyzer="image_analyzer"
                    )
                else:
                    # Add as generic binary extraction if it seems meaningful
                    if len(set(data)) > len(data) / 10:  # Basic entropy check
                        meaningful_results.append((method, data))

        # Add meaningful results that weren't high-confidence
        for method, data in meaningful_results[:5]:  # Limit to top 5 to avoid spam
            if isinstance(data, str):
                state.add_transformation(
                    name=f"Steganography Extraction - {method}",
                    description=f"Extracted text using {method}",
                    input_data=f"Image analysis via {method}",
                    output_data=data[:500] + "..." if len(data) > 500 else data,
                    analyzer="image_analyzer"
                )
            else:
                state.add_transformation(
                    name=f"Steganography Extraction - {method}",
                    description=f"Extracted binary data using {method}",
                    input_data=f"Image analysis via {method}",
                    output_data=f"Binary data ({len(data)} bytes): {data[:100].hex()}{'...' if len(data) > 100 else ''}",
                    analyzer="image_analyzer"
                )

        # Summary
        total_extractions = len(results)
        meaningful_extractions = len([r for r in results.values() if len(r) >= 16])

        state.add_insight(
            f"Advanced steganography analysis complete: {total_extractions} extractions, {meaningful_extractions} potentially meaningful",
            analyzer="image_analyzer")

        if high_confidence_results:
            state.add_insight(f"Found {len(high_confidence_results)} high-confidence hidden messages!",
                              analyzer="image_analyzer")

    except Exception as e:
        state.add_insight(f"Advanced steganography analysis failed: {e}", analyzer="image_analyzer")

    return state


def analyze_with_pil(state: State) -> None:
    """Analyze image using PIL: dimensions, mode, format, color stats, metadata"""
    try:
        img = Image.open(io.BytesIO(state.binary_data))
        width, height = img.size
        mode = img.mode
        fmt = img.format
        state.add_insight(f"Image dimensions: {width}×{height}, Mode: {mode}, Format: {fmt}", analyzer="image_analyzer")

        # Color and pattern checks
        if mode in ("RGB", "RGBA"):
            analyze_rgb_image(state, img)
        elif mode == "L":
            analyze_grayscale_image(state, img)
        elif mode == "P":
            analyze_palette_image(state, img)

        # Metadata
        analyze_image_metadata(state, img)

    except Exception as e:
        state.add_insight(f"PIL analysis failed: {e}", analyzer="image_analyzer")


def analyze_rgb_image(state: State, image) -> None:
    """Analyze RGB image for suspicious patterns"""
    try:
        pixels = list(image.getdata())
        total = len(pixels)
        if total == 0:
            return

        unique = len(set(pixels))
        state.add_insight(f"{unique} unique colors out of {total} pixels", analyzer="image_analyzer")

        if unique < 10 and total > 1000:
            state.add_insight("Very few unique colors; possible hidden info", analyzer="image_analyzer")

        # Heuristic LSB suspicion
        if unique < 16:
            state.add_insight("Low color diversity suggests LSB stego", analyzer="image_analyzer")
    except Exception as e:
        state.add_insight(f"RGB analysis failed: {e}", analyzer="image_analyzer")


def analyze_grayscale_image(state: State, image) -> None:
    """Analyze grayscale image for suspicious patterns"""
    try:
        vals = list(image.getdata())
        total = len(vals)
        if total == 0:
            return

        unique = len(set(vals))
        state.add_insight(f"{unique} gray levels out of {total} pixels", analyzer="image_analyzer")

        if unique < 5 and total > 1000:
            state.add_insight("Low gray diversity; possible hidden info", analyzer="image_analyzer")
    except Exception as e:
        state.add_insight(f"Grayscale analysis failed: {e}", analyzer="image_analyzer")


def analyze_palette_image(state: State, image) -> None:
    """Analyze palette-based image"""
    try:
        if not getattr(image, "palette", None):
            return

        palette = image.palette.palette or b""
        size = len(palette) // 3
        state.add_insight(f"Palette size: {size} colors", analyzer="image_analyzer")

        used = set(image.getdata())
        if len(used) < size:
            state.add_insight(f"Used {len(used)} of {size} palette entries; unused may hide data",
                              analyzer="image_analyzer")
    except Exception as e:
        state.add_insight(f"Palette analysis failed: {e}", analyzer="image_analyzer")


def analyze_image_metadata(state: State, image) -> None:
    """Extract and analyze image metadata"""
    try:
        # EXIF data
        if hasattr(image, "_getexif") and image._getexif():
            raw = image._getexif()
            exif = {ExifTags.TAGS.get(k, k): v for k, v in raw.items()}

            keep = []
            for tag in ("Artist", "Copyright", "UserComment", "ImageDescription"):
                if tag in exif:
                    keep.append(f"{tag}: {exif[tag]}")

            if keep:
                summary = "\n".join(keep)
                state.add_transformation(
                    name="EXIF Metadata",
                    description="Selected EXIF fields",
                    input_data=state.file_type,
                    output_data=summary,
                    analyzer="image_analyzer"
                )

        # PNG text chunks
        if image.format == "PNG" and hasattr(image, "text") and image.text:
            lines = [f"{k}: {v}" for k, v in image.text.items()]
            body = "\n".join(lines)
            state.add_transformation(
                name="PNG Text Chunks",
                description="Metadata text in PNG",
                input_data="PNG",
                output_data=body,
                analyzer="image_analyzer"
            )

            # Set as puzzle text if not already set
            if not state.puzzle_text:
                state.set_puzzle_text(body)

    except Exception as e:
        state.add_insight(f"Metadata analysis failed: {e}", analyzer="image_analyzer")


def extract_text_from_image(state: State) -> None:
    """Extract ASCII/UTF-8 strings from raw image data"""
    try:
        data = state.binary_data
        skip = {"png": 24, "jpeg": 2, "gif": 13, "bmp": 54}.get(state.file_type, 0)
        if len(data) > skip:
            data = data[skip:]

        strings = find_strings(data, min_length=5)
        if not strings:
            return

        state.add_insight(f"Found {len(strings)} raw text strings", analyzer="image_analyzer")

        # Filter out common image-related strings
        filtered = [s for s, _ in strings if not re.search(r"(adobe|jpeg|png|exif|http)", s, re.I)]

        if filtered:
            sample = filtered if len(filtered) <= 20 else filtered[:20] + [f"[...and {len(filtered) - 20} more...]"]
            text = "\n".join(sample)

            state.add_transformation(
                name="Image Text Extraction",
                description="ASCII/UTF-8 strings from image data",
                input_data=f"bytes[{len(data)}]",
                output_data=text,
                analyzer="image_analyzer"
            )

            # Set as puzzle text if not already set and looks meaningful
            if not state.puzzle_text and len(text.strip()) > 20:
                state.set_puzzle_text(text.strip())

    except Exception as e:
        state.add_insight(f"Text extraction failed: {e}", analyzer="image_analyzer")


def check_basic_lsb_steganography(state: State) -> None:
    """Basic LSB steganography detection"""
    if not HAS_PIL:
        return

    try:
        img = Image.open(io.BytesIO(state.binary_data))
        mode = img.mode

        if mode not in ("RGB", "RGBA", "L", "LA"):
            state.add_insight(f"Mode {mode} not optimal for LSB", analyzer="image_analyzer")
            return

        width, height = img.size
        total = width * height

        if total > 50000:  # Large image - sample only
            state.add_insight(f"Large image ({width}×{height}); sampling for LSB analysis", analyzer="image_analyzer")
            # Sample from corners and center
            regions = [
                (0, 0, width // 10, height // 10),
                (width * 9 // 10, 0, width, height // 10),
                (0, height * 9 // 10, width // 10, height),
                (width * 9 // 10, height * 9 // 10, width, height),
                (width // 3, height // 3, width * 2 // 3, height * 2 // 3)
            ]
        else:
            regions = [(0, 0, width, height)]  # Analyze entire image

        for i, (x1, y1, x2, y2) in enumerate(regions):
            try:
                # Extract LSB data from this region
                cropped = img.crop((x1, y1, x2, y2))

                if mode in ("RGB", "RGBA"):
                    # Try each color channel
                    for channel, name in enumerate(["Red", "Green", "Blue"]):
                        lsb_data = extract_lsb_channel(cropped, channel)
                        if lsb_data and has_pattern_in_lsb(lsb_data):
                            state.add_insight(f"Potential LSB data in {name} channel, region {i + 1}",
                                              analyzer="image_analyzer")

                            # Try to extract meaningful text
                            try:
                                text = lsb_bits_to_text(lsb_data)
                                if text and len(text.strip()) > 5:
                                    state.add_transformation(
                                        name=f"LSB Steganography - {name} Channel",
                                        description=f"Extracted text from {name} channel LSBs",
                                        input_data=f"Region {i + 1} LSB extraction",
                                        output_data=text,
                                        analyzer="image_analyzer"
                                    )

                                    # Set as puzzle text if not already set
                                    if not state.puzzle_text:
                                        state.set_puzzle_text(text.strip())
                            except:
                                pass

                elif mode in ("L", "LA"):
                    # Grayscale LSB
                    lsb_data = extract_lsb_channel(cropped, 0)
                    if lsb_data and has_pattern_in_lsb(lsb_data):
                        state.add_insight(f"Potential LSB data in grayscale, region {i + 1}", analyzer="image_analyzer")

                        try:
                            text = lsb_bits_to_text(lsb_data)
                            if text and len(text.strip()) > 5:
                                state.add_transformation(
                                    name="LSB Steganography - Grayscale",
                                    description="Extracted text from grayscale LSBs",
                                    input_data=f"Region {i + 1} LSB extraction",
                                    output_data=text,
                                    analyzer="image_analyzer"
                                )

                                if not state.puzzle_text:
                                    state.set_puzzle_text(text.strip())
                        except:
                            pass

            except Exception as e:
                continue  # Skip failed regions

    except Exception as e:
        state.add_insight(f"LSB analysis failed: {e}", analyzer="image_analyzer")


def extract_lsb_channel(image, channel: int) -> Optional[str]:
    """Extract LSB bits from a specific channel"""
    try:
        pixels = list(image.getdata())
        bits = []

        for pixel in pixels:
            if isinstance(pixel, int):  # Grayscale
                bits.append(str(pixel & 1))
            else:  # RGB/RGBA
                if channel < len(pixel):
                    bits.append(str(pixel[channel] & 1))

        return ''.join(bits)
    except:
        return None


def has_pattern_in_lsb(bit_string: str) -> bool:
    """Check if LSB bit string has suspicious patterns"""
    if not bit_string or len(bit_string) < 64:
        return False

    # Check for non-random distribution
    ones = bit_string.count('1')
    zeros = bit_string.count('0')
    total = len(bit_string)

    # Should be roughly 50/50 for natural images
    ratio = min(ones, zeros) / max(ones, zeros) if max(ones, zeros) > 0 else 0

    if ratio < 0.3:  # Very skewed
        return True

    # Check for repeating patterns
    for pattern_len in [8, 16, 32]:
        if pattern_len > len(bit_string):
            continue

        pattern = bit_string[:pattern_len]
        if bit_string.count(pattern) > len(bit_string) // (pattern_len * 2):
            return True

    return False


def lsb_bits_to_text(bit_string: str) -> Optional[str]:
    """Convert LSB bit string to text"""
    try:
        # Convert bits to bytes
        bytes_data = []
        for i in range(0, len(bit_string), 8):
            if i + 8 <= len(bit_string):
                byte_bits = bit_string[i:i + 8]
                byte_val = int(byte_bits, 2)
                bytes_data.append(byte_val)

        # Try to decode as text
        text = bytes(bytes_data).decode('utf-8', errors='ignore')

        # Filter out non-printable characters
        printable_text = ''.join(c for c in text if c.isprintable())

        return printable_text if len(printable_text) > 5 else None
    except:
        return None


def check_embedded_files(state: State) -> None:
    """Check for files embedded within the image"""
    try:
        data = state.binary_data
        signatures = {
            b"PK\x03\x04": "ZIP",
            b"Rar!\x1A\x07": "RAR",
            b"\x1F\x8B\x08": "GZIP",
            b"%PDF": "PDF",
            b"\x89PNG": "PNG",
            b"GIF": "GIF",
            b"ID3": "MP3",
            b"\x00\x00\x00\x18ftyp": "MP4"
        }

        found = []
        for sig, fmt in signatures.items():
            pos = data.find(sig)
            if pos > 0:  # Not at the beginning
                found.append((pos, fmt))

        if not found:
            return

        state.add_insight(f"Embedded files detected at offsets: {', '.join(str(p) for p, _ in found)}",
                          analyzer="image_analyzer")

        # Extract the first embedded file
        pos, fmt = found[0]

        if fmt == "ZIP":
            # Try to find end of ZIP
            eocd = data.rfind(b"PK\x05\x06")
            if eocd > pos:
                chunk = data[pos:eocd + 22]
                state.add_transformation(
                    name="Extracted ZIP Archive",
                    description="ZIP file embedded in image",
                    input_data=f"Offset {pos}",
                    output_data=f"ZIP archive ({len(chunk)} bytes)",
                    analyzer="image_analyzer"
                )
        else:
            # Extract a reasonable chunk
            chunk = data[pos:pos + 1024]  # First 1KB
            state.add_transformation(
                name=f"Embedded {fmt} File",
                description=f"{fmt} file embedded in image",
                input_data=f"Offset {pos}",
                output_data=f"{fmt} data ({len(chunk)} bytes): {chunk[:100].hex()}{'...' if len(chunk) > 100 else ''}",
                analyzer="image_analyzer"
            )

    except Exception as e:
        state.add_insight(f"Embedded file check failed: {e}", analyzer="image_analyzer")


# Compatibility with OpenCV-based fallback
def analyze_image_with_opencv(state: State) -> State:
    """Fallback analysis using OpenCV when vision API is not available"""
    state.add_insight("Using OpenCV-based image analysis (vision API not available)", analyzer="image_analyzer")

    # Run the main analysis function
    return analyze_image(state)