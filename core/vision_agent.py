"""
Vision Agent Module
Real implementation for comprehensive image analysis, OCR, steganography detection, and visual pattern recognition.
"""

import logging
import io
import hashlib
import struct
from typing import Dict, List, Optional, Any, Tuple
import numpy as np

logger = logging.getLogger(__name__)

class VisionAgent:
    """
    Production agent for comprehensive visual analysis of images and visual content.
    """

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.name = "VisionAgent"

        # Try to import required libraries
        self.libs_available = self._check_dependencies()

        logger.debug("VisionAgent initialized with real implementation")

    def _check_dependencies(self) -> Dict[str, bool]:
        """Check which vision libraries are available."""
        libs = {}

        try:
            from PIL import Image, ImageStat, ImageFilter, ExifTags
            libs['PIL'] = True
        except ImportError:
            libs['PIL'] = False
            logger.warning("PIL/Pillow not available - limited image analysis")

        try:
            import cv2
            libs['opencv'] = True
        except ImportError:
            libs['opencv'] = False
            logger.warning("OpenCV not available - no advanced image processing")

        try:
            import pytesseract
            libs['ocr'] = True
        except ImportError:
            libs['ocr'] = False
            logger.warning("Tesseract OCR not available")

        try:
            import pyzbar.pyzbar as pyzbar
            libs['barcode'] = True
        except ImportError:
            libs['barcode'] = False
            logger.warning("Pyzbar not available - no barcode detection")

        return libs

    def run(self, state):
        """
        Perform comprehensive visual analysis on all image materials.
        """
        try:
            if self.verbose:
                logger.info("🔍 Running comprehensive vision analysis...")

            analysis_results = []

            for material_id, material in state.materials.items():
                if self._is_image_material(material):
                    result = self._analyze_image(material)
                    if result:
                        analysis_results.append(result)

                        # Add findings to state
                        for finding in result.get('findings', []):
                            state.add_insight(finding, "vision_agent")

                        # Add extracted text as new materials if significant
                        if result.get('extracted_text'):
                            self._add_text_material(state, result['extracted_text'], material)

            if analysis_results:
                total_findings = sum(len(r.get('findings', [])) for r in analysis_results)
                summary = f"Analyzed {len(analysis_results)} images, found {total_findings} visual insights"
                state.add_insight(summary, "vision_agent")

            logger.info("Vision analysis completed")
            return state

        except Exception as e:
            logger.error(f"Error in VisionAgent.run: {e}")
            return state

    def _is_image_material(self, material) -> bool:
        """Check if material is an image."""
        if not hasattr(material, 'content') or not isinstance(material.content, bytes):
            return False

        data = material.content
        if len(data) < 8:
            return False

        # Check image signatures
        image_signatures = [
            b'\x89PNG\r\n\x1a\n',  # PNG
            b'\xFF\xD8\xFF',        # JPEG
            b'GIF87a',              # GIF87a
            b'GIF89a',              # GIF89a
            b'BM',                  # BMP
            b'RIFF',                # RIFF (WebP/other)
        ]

        return any(data.startswith(sig) for sig in image_signatures) or \
               (data.startswith(b'RIFF') and b'WEBP' in data[:12])

    def _analyze_image(self, material) -> Optional[Dict[str, Any]]:
        """
        Comprehensive analysis of a single image.
        """
        try:
            data = material.content
            filename = getattr(material, 'name', 'unknown')

            result = {
                'filename': filename,
                'findings': [],
                'metadata': {},
                'extracted_text': [],
                'visual_features': {}
            }

            if not self.libs_available.get('PIL', False):
                result['findings'].append("PIL not available - using basic analysis")
                return self._basic_image_analysis(data, result)

            # Load image with PIL
            from PIL import Image, ImageStat, ImageFilter, ExifTags

            try:
                image = Image.open(io.BytesIO(data))
                result['metadata']['format'] = image.format
                result['metadata']['size'] = image.size
                result['metadata']['mode'] = image.mode

                # Basic image info
                width, height = image.size
                result['findings'].append(f"Image: {width}x{height}, {image.mode} mode, {image.format} format")

                # EXIF analysis
                exif_data = self._extract_exif(image)
                if exif_data:
                    result['metadata']['exif'] = exif_data
                    result['findings'].append(f"EXIF data found: {len(exif_data)} fields")

                # Statistical analysis
                stats = self._analyze_image_statistics(image)
                result['visual_features'].update(stats)

                # Steganography detection
                stego_results = self._detect_steganography(image, data)
                if stego_results:
                    result['findings'].extend(stego_results)

                # OCR text extraction
                if self.libs_available.get('ocr', False):
                    text_results = self._extract_text_ocr(image)
                    if text_results:
                        result['extracted_text'] = text_results
                        result['findings'].append(f"OCR extracted {len(text_results)} text regions")

                # QR/Barcode detection
                if self.libs_available.get('barcode', False):
                    barcode_results = self._detect_barcodes(image)
                    if barcode_results:
                        result['findings'].extend([f"Barcode/QR: {br}" for br in barcode_results])

                # Advanced analysis with OpenCV
                if self.libs_available.get('opencv', False):
                    opencv_results = self._opencv_analysis(data)
                    if opencv_results:
                        result['findings'].extend(opencv_results.get('findings', []))
                        result['visual_features'].update(opencv_results.get('features', {}))

                # Color analysis
                color_analysis = self._analyze_colors(image)
                if color_analysis:
                    result['findings'].extend(color_analysis)

                # Look for hidden patterns
                pattern_results = self._detect_visual_patterns(image)
                if pattern_results:
                    result['findings'].extend(pattern_results)

            except Exception as e:
                result['findings'].append(f"Image processing error: {str(e)}")
                return self._basic_image_analysis(data, result)

            return result

        except Exception as e:
            logger.error(f"Error analyzing image {getattr(material, 'name', 'unknown')}: {e}")
            return None

    def _basic_image_analysis(self, data: bytes, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Basic image analysis without PIL.
        """
        # Analyze raw bytes for patterns
        result['findings'].append("Performing basic byte-level image analysis")

        # Look for repeated patterns (potential steganography)
        chunk_size = 1024
        chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
        unique_chunks = len(set(chunks))

        if len(chunks) > 0:
            repetition_ratio = unique_chunks / len(chunks)
            if repetition_ratio < 0.8:
                result['findings'].append(f"High repetition in data (ratio: {repetition_ratio:.2f}) - possible pattern")

        # Look for embedded signatures
        common_sigs = [b'PK\x03\x04', b'\x89PNG', b'\xFF\xD8\xFF', b'GIF8', b'%PDF']
        for i, sig in enumerate(common_sigs):
            positions = []
            start = 0
            while True:
                pos = data.find(sig, start)
                if pos == -1:
                    break
                positions.append(pos)
                start = pos + 1

            if len(positions) > 1:
                result['findings'].append(f"Multiple {['ZIP', 'PNG', 'JPEG', 'GIF', 'PDF'][i]} signatures at offsets: {positions[:5]}")

        return result

    def _extract_exif(self, image) -> Optional[Dict[str, Any]]:
        """
        Extract and analyze EXIF data.
        """
        try:
            from PIL.ExifTags import TAGS, GPSTAGS

            exif_dict = {}
            if hasattr(image, '_getexif'):
                exif = image._getexif()
                if exif:
                    for tag_id, value in exif.items():
                        tag = TAGS.get(tag_id, tag_id)
                        exif_dict[tag] = value

                        # Look for GPS data
                        if tag == 'GPSInfo':
                            gps_data = {}
                            for gps_tag_id, gps_value in value.items():
                                gps_tag = GPSTAGS.get(gps_tag_id, gps_tag_id)
                                gps_data[gps_tag] = gps_value
                            exif_dict['GPSInfo'] = gps_data

            return exif_dict if exif_dict else None

        except Exception as e:
            logger.debug(f"EXIF extraction error: {e}")
            return None

    def _analyze_image_statistics(self, image) -> Dict[str, Any]:
        """
        Analyze image statistics for anomalies.
        """
        try:
            from PIL import ImageStat

            stats = {}

            # Convert to RGB if needed
            if image.mode in ['RGBA', 'LA']:
                rgb_image = image.convert('RGB')
            elif image.mode == 'P':
                rgb_image = image.convert('RGB')
            else:
                rgb_image = image

            # Calculate statistics
            stat = ImageStat.Stat(rgb_image)

            stats['mean'] = stat.mean
            stats['median'] = stat.median
            stats['stddev'] = stat.stddev
            stats['extrema'] = stat.extrema

            # Detect unusual distributions
            if len(stat.mean) >= 3:  # RGB
                # Check if any channel is heavily skewed
                for i, (mean, std) in enumerate(zip(stat.mean, stat.stddev)):
                    channel = ['Red', 'Green', 'Blue'][i]
                    if std < 10:  # Very low variance
                        stats[f'{channel.lower()}_anomaly'] = f"Very low variance ({std:.1f})"
                    elif mean < 30 or mean > 225:  # Extreme values
                        stats[f'{channel.lower()}_anomaly'] = f"Extreme mean value ({mean:.1f})"

            return stats

        except Exception as e:
            logger.debug(f"Statistics analysis error: {e}")
            return {}

    def _detect_steganography(self, image, raw_data: bytes) -> List[str]:
        """
        Detect potential steganography using multiple techniques.
        """
        findings = []

        try:
            # LSB analysis
            lsb_results = self._analyze_lsb(image)
            if lsb_results:
                findings.extend(lsb_results)

            # Chi-square test for randomness
            chi_results = self._chi_square_analysis(raw_data)
            if chi_results:
                findings.append(chi_results)

            # Frequency analysis
            freq_results = self._frequency_analysis(image)
            if freq_results:
                findings.extend(freq_results)

            # Metadata hiding detection
            metadata_results = self._detect_metadata_hiding(raw_data)
            if metadata_results:
                findings.extend(metadata_results)

        except Exception as e:
            logger.debug(f"Steganography detection error: {e}")

        return findings

    def _analyze_lsb(self, image) -> List[str]:
        """
        Analyze Least Significant Bits for hidden data.
        """
        findings = []

        try:
            # Convert to numpy array for analysis
            import numpy as np

            if image.mode == 'RGB':
                img_array = np.array(image)

                # Extract LSBs
                lsb_data = img_array & 1

                # Calculate entropy of LSB data
                lsb_flat = lsb_data.flatten()
                unique, counts = np.unique(lsb_flat, return_counts=True)

                if len(unique) > 1:
                    # Calculate entropy
                    probabilities = counts / len(lsb_flat)
                    entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))

                    if entropy > 0.9:  # High entropy in LSBs
                        findings.append(f"High LSB entropy ({entropy:.3f}) - possible LSB steganography")

                    # Check for patterns in LSBs
                    lsb_diff = np.diff(lsb_flat)
                    pattern_score = np.std(lsb_diff)

                    if pattern_score < 0.4:  # Low variance in differences
                        findings.append(f"LSB pattern detected (score: {pattern_score:.3f})")

        except Exception as e:
            logger.debug(f"LSB analysis error: {e}")

        return findings

    def _chi_square_analysis(self, data: bytes) -> Optional[str]:
        """
        Perform chi-square test on image data.
        """
        try:
            import numpy as np
            from scipy import stats

            # Convert bytes to array
            byte_array = np.frombuffer(data, dtype=np.uint8)

            # Expected frequency for uniform distribution
            expected_freq = len(byte_array) / 256

            # Observed frequencies
            observed_freq = np.bincount(byte_array, minlength=256)

            # Chi-square test
            chi2_stat, p_value = stats.chisquare(observed_freq, expected_freq)

            if p_value < 0.01:  # Highly non-random
                return f"Chi-square test: non-random data (p={p_value:.6f})"
            elif p_value > 0.99:  # Too random (possible encryption/steganography)
                return f"Chi-square test: suspiciously random data (p={p_value:.6f})"

        except ImportError:
            # Fallback without scipy
            pass
        except Exception as e:
            logger.debug(f"Chi-square analysis error: {e}")

        return None

    def _frequency_analysis(self, image) -> List[str]:
        """
        Analyze pixel value frequencies for anomalies.
        """
        findings = []

        try:
            import numpy as np

            img_array = np.array(image)

            if len(img_array.shape) == 3:  # Color image
                for channel, name in enumerate(['Red', 'Green', 'Blue']):
                    channel_data = img_array[:, :, channel].flatten()

                    # Calculate histogram
                    hist, _ = np.histogram(channel_data, bins=256, range=(0, 256))

                    # Look for unusual spikes or gaps
                    max_freq = np.max(hist)
                    mean_freq = np.mean(hist)

                    if max_freq > mean_freq * 5:  # Very uneven distribution
                        max_val = np.argmax(hist)
                        findings.append(f"{name} channel: unusual spike at value {max_val}")

                    # Look for suspicious gaps
                    zero_bins = np.sum(hist == 0)
                    if zero_bins > 100:  # Many empty bins
                        findings.append(f"{name} channel: {zero_bins} empty value bins (suspicious)")

        except Exception as e:
            logger.debug(f"Frequency analysis error: {e}")

        return findings

    def _detect_metadata_hiding(self, data: bytes) -> List[str]:
        """
        Look for data hidden in metadata sections.
        """
        findings = []

        try:
            # Look for unusually large metadata sections
            if data.startswith(b'\xFF\xD8\xFF'):  # JPEG
                # Find APP segments
                offset = 2
                while offset < len(data) - 4:
                    if data[offset] == 0xFF and 0xE0 <= data[offset + 1] <= 0xEF:
                        segment_length = struct.unpack('>H', data[offset + 2:offset + 4])[0]
                        if segment_length > 10000:  # Unusually large metadata
                            findings.append(f"Large metadata segment: {segment_length} bytes")
                        offset += 2 + segment_length
                    else:
                        break

            elif data.startswith(b'\x89PNG'):  # PNG
                # Check for large text chunks
                offset = 8
                while offset < len(data) - 12:
                    try:
                        chunk_length = struct.unpack('>I', data[offset:offset + 4])[0]
                        chunk_type = data[offset + 4:offset + 8]

                        if chunk_type in [b'tEXt', b'zTXt', b'iTXt'] and chunk_length > 1000:
                            findings.append(f"Large PNG text chunk: {chunk_length} bytes")

                        offset += 8 + chunk_length + 4
                    except struct.error:
                        break

        except Exception as e:
            logger.debug(f"Metadata hiding detection error: {e}")

        return findings

    def _extract_text_ocr(self, image) -> List[Dict[str, Any]]:
        """
        Extract text using OCR.
        """
        try:
            import pytesseract

            # Extract text with position information
            data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)

            text_regions = []
            for i in range(len(data['text'])):
                text = data['text'][i].strip()
                if text and int(data['conf'][i]) > 30:  # Confidence threshold
                    text_regions.append({
                        'text': text,
                        'confidence': int(data['conf'][i]),
                        'bbox': (data['left'][i], data['top'][i], data['width'][i], data['height'][i])
                    })

            return text_regions

        except Exception as e:
            logger.debug(f"OCR extraction error: {e}")
            return []

    def _detect_barcodes(self, image) -> List[str]:
        """
        Detect QR codes and barcodes.
        """
        try:
            import pyzbar.pyzbar as pyzbar

            # Detect barcodes
            barcodes = pyzbar.decode(image)

            results = []
            for barcode in barcodes:
                barcode_data = barcode.data.decode('utf-8')
                barcode_type = barcode.type
                results.append(f"{barcode_type}: {barcode_data}")

            return results

        except Exception as e:
            logger.debug(f"Barcode detection error: {e}")
            return []

    def _opencv_analysis(self, data: bytes) -> Optional[Dict[str, Any]]:
        """
        Advanced analysis using OpenCV.
        """
        try:
            import cv2
            import numpy as np

            # Load image
            img_array = np.frombuffer(data, np.uint8)
            img = cv2.imdecode(img_array, cv2.IMREAD_COLOR)

            if img is None:
                return None

            result = {'findings': [], 'features': {}}

            # Edge detection
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            edges = cv2.Canny(gray, 50, 150)
            edge_density = np.sum(edges > 0) / edges.size

            result['features']['edge_density'] = edge_density
            if edge_density > 0.1:
                result['findings'].append(f"High edge density ({edge_density:.3f}) - detailed image")
            elif edge_density < 0.01:
                result['findings'].append(f"Low edge density ({edge_density:.3f}) - smooth/artificial image")

            # Contour detection
            contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            result['features']['contour_count'] = len(contours)

            # Look for geometric shapes
            geometric_shapes = 0
            for contour in contours:
                # Approximate contour to polygon
                epsilon = 0.02 * cv2.arcLength(contour, True)
                approx = cv2.approxPolyDP(contour, epsilon, True)

                # Count geometric shapes (triangles, rectangles, etc.)
                if 3 <= len(approx) <= 8 and cv2.contourArea(contour) > 100:
                    geometric_shapes += 1

            if geometric_shapes > 10:
                result['findings'].append(f"Many geometric shapes detected ({geometric_shapes}) - possibly synthetic")

            # Template matching for common patterns
            self._detect_patterns_opencv(img, result)

            return result

        except Exception as e:
            logger.debug(f"OpenCV analysis error: {e}")
            return None

    def _detect_patterns_opencv(self, img, result: Dict[str, Any]):
        """
        Detect specific patterns using template matching.
        """
        try:
            import cv2
            import numpy as np

            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

            # Create simple templates for common patterns
            templates = {
                'qr_corner': np.array([
                    [255, 255, 255, 255, 255, 255, 255],
                    [255, 0, 0, 0, 0, 0, 255],
                    [255, 0, 255, 255, 255, 0, 255],
                    [255, 0, 255, 255, 255, 0, 255],
                    [255, 0, 255, 255, 255, 0, 255],
                    [255, 0, 0, 0, 0, 0, 255],
                    [255, 255, 255, 255, 255, 255, 255]
                ], dtype=np.uint8),

                'checkerboard': np.array([
                    [255, 0, 255, 0],
                    [0, 255, 0, 255],
                    [255, 0, 255, 0],
                    [0, 255, 0, 255]
                ], dtype=np.uint8)
            }

            for pattern_name, template in templates.items():
                res = cv2.matchTemplate(gray, template, cv2.TM_CCOEFF_NORMED)
                locations = np.where(res >= 0.7)

                if len(locations[0]) > 0:
                    result['findings'].append(f"{pattern_name.replace('_', ' ').title()} pattern detected")

        except Exception as e:
            logger.debug(f"Pattern detection error: {e}")

    def _analyze_colors(self, image) -> List[str]:
        """
        Analyze color distribution and palette.
        """
        findings = []

        try:
            # Get dominant colors
            colors = image.getcolors(maxcolors=256*256*256)
            if colors:
                # Sort by frequency
                colors.sort(reverse=True)

                # Check if image is mostly monochrome
                if len(colors) < 10:
                    findings.append(f"Limited color palette ({len(colors)} colors) - possibly synthetic")

                # Check for unusual color dominance
                total_pixels = sum(count for count, color in colors)
                dominant_ratio = colors[0][0] / total_pixels

                if dominant_ratio > 0.8:
                    findings.append(f"Single color dominance ({dominant_ratio:.1%}) - unusual distribution")

                # Look for suspicious color patterns
                if len(colors) > 100:
                    # Check if colors are too evenly distributed
                    expected_count = total_pixels / len(colors)
                    variance = sum((count - expected_count) ** 2 for count, color in colors) / len(colors)

                    if variance < expected_count * 0.1:
                        findings.append("Unusually even color distribution - possible artificial generation")

        except Exception as e:
            logger.debug(f"Color analysis error: {e}")

        return findings

    def _detect_visual_patterns(self, image) -> List[str]:
        """
        Detect repetitive visual patterns that might indicate hidden data.
        """
        findings = []

        try:
            import numpy as np

            # Convert to grayscale for pattern analysis
            if image.mode != 'L':
                gray_image = image.convert('L')
            else:
                gray_image = image

            img_array = np.array(gray_image)

            # Look for horizontal patterns
            horizontal_diff = np.diff(img_array, axis=1)
            h_pattern_score = np.std(horizontal_diff)

            if h_pattern_score < 10:
                findings.append(f"Strong horizontal patterns detected (score: {h_pattern_score:.1f})")

            # Look for vertical patterns
            vertical_diff = np.diff(img_array, axis=0)
            v_pattern_score = np.std(vertical_diff)

            if v_pattern_score < 10:
                findings.append(f"Strong vertical patterns detected (score: {v_pattern_score:.1f})")

            # Check for block patterns (8x8, 16x16)
            for block_size in [8, 16]:
                if img_array.shape[0] % block_size == 0 and img_array.shape[1] % block_size == 0:
                    blocks = []
                    for i in range(0, img_array.shape[0], block_size):
                        for j in range(0, img_array.shape[1], block_size):
                            block = img_array[i:i+block_size, j:j+block_size]
                            blocks.append(block.flatten())

                    # Check for repeated blocks
                    unique_blocks = len(set(tuple(block) for block in blocks))
                    repetition_ratio = unique_blocks / len(blocks)

                    if repetition_ratio < 0.7:
                        findings.append(f"{block_size}x{block_size} block repetition detected (ratio: {repetition_ratio:.2f})")

        except Exception as e:
            logger.debug(f"Pattern detection error: {e}")

        return findings

    def _add_text_material(self, state, text_regions: List[Dict[str, Any]], parent_material):
        """
        Add extracted text as new material if significant.
        """
        try:
            # Combine all text
            all_text = ' '.join([region['text'] for region in text_regions])

            if len(all_text.strip()) > 10:  # Only if substantial text
                # Add as insight for now - could create new material
                state.add_insight(f"OCR extracted text: {all_text[:200]}{'...' if len(all_text) > 200 else ''}", "vision_agent")

                # Look for interesting patterns in extracted text
                import re

                # Bitcoin addresses
                btc_addresses = re.findall(r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}', all_text)
                if btc_addresses:
                    state.add_insight(f"Bitcoin addresses found in text: {', '.join(btc_addresses[:3])}", "vision_agent")

                # Ethereum addresses
                eth_addresses = re.findall(r'0x[a-fA-F0-9]{40}', all_text)
                if eth_addresses:
                    state.add_insight(f"Ethereum addresses found in text: {', '.join(eth_addresses[:3])}", "vision_agent")

                # Hash-like strings
                hashes = re.findall(r'[a-fA-F0-9]{32,64}', all_text)
                if hashes:
                    state.add_insight(f"Hash-like strings found: {len(hashes)} potential hashes", "vision_agent")

        except Exception as e:
            logger.error(f"Error processing extracted text: {e}")