"""
Text Extractor Agent Module
Extracts and analyzes text content from various file formats.
"""

import logging
import re
import base64
import binascii
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class TextExtractorAgent:
    """
    Agent responsible for extracting text from various file formats.
    """

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.name = "TextExtractorAgent"
        logger.debug("TextExtractorAgent initialized")

    def run(self, state):
        try:
            if self.verbose:
                logger.info("🔍 Running text extraction...")

            findings_count = 0

            # Extract text from all materials
            for material_id, material in state.materials.items():
                try:
                    findings_count += self._extract_from_material(state, material)
                except Exception as e:
                    logger.warning(f"TextExtractorAgent failed on {material_id}: {e}")

            logger.info(f"Text extraction completed - found {findings_count} insights")
            return state

        except Exception as e:
            logger.error(f"Error in TextExtractorAgent.run: {e}")
            return state

    def _extract_from_material(self, state, material):
        """Extract text content from a material."""
        findings_count = 0

        try:
            content = material.content

            # Handle different content types
            if isinstance(content, bytes):
                findings_count += self._extract_from_binary(state, material, content)
            elif isinstance(content, str):
                findings_count += self._extract_from_text(state, material, content)

        except Exception as e:
            logger.error(f"Error extracting from {material.name}: {e}")

        return findings_count

    def _extract_from_binary(self, state, material, data):
        """Extract text from binary data."""
        findings_count = 0

        try:
            # Try different text extraction methods
            findings_count += self._extract_ascii_strings(state, material, data)
            findings_count += self._extract_utf8_text(state, material, data)
            findings_count += self._extract_encoded_text(state, material, data)
            findings_count += self._extract_metadata_text(state, material, data)

        except Exception as e:
            logger.error(f"Error extracting from binary data: {e}")

        return findings_count

    def _extract_ascii_strings(self, state, material, data):
        """Extract ASCII strings from binary data."""
        findings_count = 0

        try:
            strings = []
            current_string = ""

            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += chr(byte)
                else:
                    if len(current_string) >= 4:
                        strings.append(current_string)
                    current_string = ""

            # Don't forget the last string
            if len(current_string) >= 4:
                strings.append(current_string)

            if strings:
                state.add_insight(f"Extracted {len(strings)} ASCII strings from {material.name}", "text_extractor")
                findings_count += 1

                # Look for interesting strings
                crypto_strings = [s for s in strings if self._is_crypto_related(s)]
                if crypto_strings:
                    state.add_insight(f"Found {len(crypto_strings)} crypto-related strings", "text_extractor")
                    findings_count += 1

                    # Add specific crypto strings
                    for crypto_str in crypto_strings[:5]:  # First 5
                        state.add_insight(f"Crypto string: {crypto_str[:50]}...", "text_extractor")
                        findings_count += 1

                # Look for URLs
                urls = [s for s in strings if self._is_url(s)]
                if urls:
                    state.add_insight(f"Found {len(urls)} URLs in text", "text_extractor")
                    findings_count += 1
                    for url in urls[:3]:  # First 3 URLs
                        state.add_insight(f"URL found: {url}", "text_extractor")
                        findings_count += 1

        except Exception as e:
            logger.error(f"Error extracting ASCII strings: {e}")

        return findings_count

    def _extract_utf8_text(self, state, material, data):
        """Try to extract UTF-8 text from binary data."""
        findings_count = 0

        try:
            # Try to decode entire content as UTF-8
            try:
                text = data.decode('utf-8')
                if len(text.strip()) > 20:  # Substantial text content
                    state.add_insight(f"Successfully decoded {len(text)} UTF-8 characters", "text_extractor")
                    findings_count += 1

                    # Analyze the decoded text
                    findings_count += self._analyze_text_content(state, material, text)

            except UnicodeDecodeError:
                # Try partial decoding
                text = data.decode('utf-8', errors='ignore')
                if len(text.strip()) > 50:  # Only if substantial content
                    state.add_insight(f"Partial UTF-8 decode: {len(text)} characters", "text_extractor")
                    findings_count += 1

        except Exception as e:
            logger.error(f"Error extracting UTF-8 text: {e}")

        return findings_count

    def _extract_encoded_text(self, state, material, data):
        """Try to extract base64 or hex encoded text."""
        findings_count = 0

        try:
            # Look for base64 patterns
            text_data = data.decode('ascii', errors='ignore')

            # Find base64 chunks
            base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
            base64_matches = re.findall(base64_pattern, text_data)

            for match in base64_matches:
                try:
                    decoded = base64.b64decode(match)
                    decoded_text = decoded.decode('utf-8', errors='ignore')
                    if len(decoded_text.strip()) > 10:
                        state.add_insight(f"Base64 decoded text: {decoded_text[:50]}...", "text_extractor")
                        findings_count += 1
                except:
                    pass

            # Look for hex encoded text
            hex_pattern = r'[0-9a-fA-F]{20,}'
            hex_matches = re.findall(hex_pattern, text_data)

            for match in hex_matches:
                try:
                    if len(match) % 2 == 0:  # Even length for valid hex
                        decoded = bytes.fromhex(match)
                        decoded_text = decoded.decode('utf-8', errors='ignore')
                        if len(decoded_text.strip()) > 10:
                            state.add_insight(f"Hex decoded text: {decoded_text[:50]}...", "text_extractor")
                            findings_count += 1
                except:
                    pass

        except Exception as e:
            logger.error(f"Error extracting encoded text: {e}")

        return findings_count

    def _extract_metadata_text(self, state, material, data):
        """Extract text from file metadata sections."""
        findings_count = 0

        try:
            # Look for common metadata sections in PNG files
            if data.startswith(b'\x89PNG'):
                findings_count += self._extract_png_text(state, material, data)

            # Look for EXIF data in JPEG files
            elif data.startswith(b'\xFF\xD8\xFF'):
                findings_count += self._extract_jpeg_text(state, material, data)

        except Exception as e:
            logger.error(f"Error extracting metadata text: {e}")

        return findings_count

    def _extract_png_text(self, state, material, data):
        """Extract text chunks from PNG files."""
        findings_count = 0

        try:
            # Look for tEXt chunks in PNG
            pos = 0
            while pos < len(data) - 8:
                # Find tEXt chunk
                text_pos = data.find(b'tEXt', pos)
                if text_pos == -1:
                    break

                # Get chunk length (4 bytes before chunk type)
                if text_pos >= 4:
                    chunk_len = int.from_bytes(data[text_pos - 4:text_pos], 'big')
                    if chunk_len > 0 and chunk_len < 10000:  # Reasonable size
                        chunk_data = data[text_pos + 4:text_pos + 4 + chunk_len]
                        try:
                            text_content = chunk_data.decode('utf-8', errors='ignore')
                            if len(text_content.strip()) > 5:
                                state.add_insight(f"PNG text chunk: {text_content[:100]}...", "text_extractor")
                                findings_count += 1
                        except:
                            pass

                pos = text_pos + 1

        except Exception as e:
            logger.error(f"Error extracting PNG text: {e}")

        return findings_count

    def _extract_jpeg_text(self, state, material, data):
        """Extract text from JPEG EXIF data."""
        findings_count = 0

        try:
            # Look for text in EXIF data (simplified)
            strings = re.findall(b'[\x20-\x7E]{8,}', data)
            text_strings = []

            for string_bytes in strings:
                try:
                    text = string_bytes.decode('ascii')
                    if self._is_meaningful_text(text):
                        text_strings.append(text)
                except:
                    pass

            if text_strings:
                state.add_insight(f"JPEG metadata contains {len(text_strings)} text strings", "text_extractor")
                findings_count += 1

        except Exception as e:
            logger.error(f"Error extracting JPEG text: {e}")

        return findings_count

    def _extract_from_text(self, state, material, text):
        """Extract information from plain text content."""
        findings_count = 0

        try:
            findings_count += self._analyze_text_content(state, material, text)

        except Exception as e:
            logger.error(f"Error extracting from text: {e}")

        return findings_count

    def _analyze_text_content(self, state, material, text):
        """Analyze plain text content for patterns."""
        findings_count = 0

        try:
            # Look for various patterns
            findings_count += self._find_crypto_addresses(state, text)
            findings_count += self._find_private_keys(state, text)
            findings_count += self._find_seeds_mnemonics(state, text)
            findings_count += self._find_codes_ciphers(state, text)

        except Exception as e:
            logger.error(f"Error analyzing text content: {e}")

        return findings_count

    def _find_crypto_addresses(self, state, text):
        """Find cryptocurrency addresses in text."""
        findings_count = 0

        try:
            # Bitcoin addresses
            btc_pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
            btc_matches = re.findall(btc_pattern, text)
            if btc_matches:
                state.add_insight(f"Found {len(btc_matches)} potential Bitcoin addresses", "text_extractor")
                findings_count += 1

            # Ethereum addresses
            eth_pattern = r'\b0x[a-fA-F0-9]{40}\b'
            eth_matches = re.findall(eth_pattern, text)
            if eth_matches:
                state.add_insight(f"Found {len(eth_matches)} potential Ethereum addresses", "text_extractor")
                findings_count += 1

        except Exception as e:
            logger.error(f"Error finding crypto addresses: {e}")

        return findings_count

    def _find_private_keys(self, state, text):
        """Find private key patterns in text."""
        findings_count = 0

        try:
            # Look for hex private keys
            hex_key_pattern = r'\b[a-fA-F0-9]{64}\b'
            hex_keys = re.findall(hex_key_pattern, text)
            if hex_keys:
                state.add_insight(f"Found {len(hex_keys)} potential hex private keys", "text_extractor")
                findings_count += 1

        except Exception as e:
            logger.error(f"Error finding private keys: {e}")

        return findings_count

    def _find_seeds_mnemonics(self, state, text):
        """Find seed phrases and mnemonics."""
        findings_count = 0

        try:
            # Look for common seed words
            seed_words = ['abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract', 'absurd',
                          'abuse']

            words = text.lower().split()
            seed_count = sum(1 for word in words if word in seed_words)

            if seed_count >= 5:  # Multiple seed words found
                state.add_insight(f"Text contains {seed_count} BIP39 seed words - possible mnemonic", "text_extractor")
                findings_count += 1

        except Exception as e:
            logger.error(f"Error finding seeds/mnemonics: {e}")

        return findings_count

    def _find_codes_ciphers(self, state, text):
        """Find codes and cipher patterns."""
        findings_count = 0

        try:
            # Look for Base64 patterns
            base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
            base64_matches = re.findall(base64_pattern, text)
            if base64_matches:
                state.add_insight(f"Found {len(base64_matches)} Base64-like strings", "text_extractor")
                findings_count += 1

            # Look for repeated character patterns (potential cipher)
            if re.search(r'(.)\1{10,}', text):  # 10+ repeated characters
                state.add_insight("Text contains long repeated character sequences", "text_extractor")
                findings_count += 1

        except Exception as e:
            logger.error(f"Error finding codes/ciphers: {e}")

        return findings_count

    def _is_crypto_related(self, text):
        """Check if text string is crypto-related."""
        crypto_keywords = [
            'bitcoin', 'btc', 'ethereum', 'eth', 'wallet', 'private', 'key', 'seed',
            'mnemonic', 'address', 'hash', 'sha256', 'md5', 'cipher', 'encrypt',
            'decrypt', 'crypto', 'blockchain', 'satoshi'
        ]
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in crypto_keywords)

    def _is_url(self, text):
        """Check if text string is a URL."""
        url_pattern = r'https?://[^\s]+|www\.[^\s]+'
        return re.search(url_pattern, text) is not None

    def _is_meaningful_text(self, text):
        """Check if text appears to be meaningful (not random)."""
        # Basic heuristics for meaningful text
        if len(text) < 8:
            return False

        # Should have some spaces or common punctuation
        if not re.search(r'[\s.,!?;:]', text):
            return False

        # Should not be mostly numbers
        digit_ratio = sum(1 for c in text if c.isdigit()) / len(text)
        if digit_ratio > 0.8:
            return False

        return True