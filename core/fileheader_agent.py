"""
File Header Agent Module
Analyzes file headers and magic bytes to identify file types and structures.
"""

import logging

logger = logging.getLogger(__name__)


class FileHeaderAgent:
    """
    Agent responsible for analyzing file headers and magic bytes.
    """

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.name = "FileHeaderAgent"
        logger.debug("FileHeaderAgent initialized")

    def run(self, state):
        """
        Run file header analysis on all materials.
        """
        try:
            if self.verbose:
                logger.info("🔍 Running file header analysis...")

            findings_count = 0

            # Analyze each material
            for material_id, material in state.materials.items():
                if hasattr(material, 'content') and isinstance(material.content, bytes):
                    findings_count += self._analyze_file_header(state, material)

            logger.info(f"File header analysis completed - found {findings_count} insights")

            return state

        except Exception as e:
            logger.error(f"Error in FileHeaderAgent.run: {e}")
            return state

    def _analyze_file_header(self, state, material):
        """Analyze the header of a specific material."""
        findings_count = 0

        try:
            data = material.content
            if len(data) < 4:
                return findings_count

            # Check for common file signatures
            header = data[:16]  # First 16 bytes

            file_type = "unknown"
            details = []

            if header.startswith(b'\x89PNG'):
                file_type = "PNG image"
                # PNG analysis
                if len(data) > 8:
                    width = int.from_bytes(data[16:20], 'big')
                    height = int.from_bytes(data[20:24], 'big')
                    details.append(f"Dimensions: {width}x{height}")

            elif header.startswith(b'\xFF\xD8\xFF'):
                file_type = "JPEG image"
                details.append("JPEG with EXIF data possible")

            elif header.startswith(b'GIF8'):
                file_type = "GIF image"
                version = header[3:6].decode('ascii', errors='ignore')
                details.append(f"GIF version: {version}")

            elif header.startswith(b'PK\x03\x04'):
                file_type = "ZIP archive"
                details.append("May contain hidden files")

            elif header.startswith(b'\x7fELF'):
                file_type = "ELF executable"
                details.append("Linux/Unix executable")

            elif header.startswith(b'MZ'):
                file_type = "PE executable"
                details.append("Windows executable")

            elif header.startswith(b'%PDF'):
                file_type = "PDF document"
                details.append("May contain embedded content")

            # Add findings
            if file_type != "unknown":
                state.add_insight(f"File {material.name} identified as {file_type}", "fileheader_agent")
                findings_count += 1

                for detail in details:
                    state.add_insight(f"File detail: {detail}", "fileheader_agent")
                    findings_count += 1

            # Check for embedded data (look for multiple signatures)
            self._check_embedded_data(state, material, data)
            findings_count += 1

            # Look for strings in binary data
            strings_found = self._extract_strings(data)
            if strings_found:
                state.add_insight(f"Found {len(strings_found)} text strings in {material.name}", "fileheader_agent")
                findings_count += 1

                # Add interesting strings
                for string in strings_found[:5]:  # First 5 strings
                    if len(string) > 10:  # Only longer strings
                        state.add_insight(f"Text string found: {string[:50]}...", "fileheader_agent")
                        findings_count += 1

        except Exception as e:
            logger.error(f"Error analyzing file header for {material.name}: {e}")

        return findings_count

    def _check_embedded_data(self, state, material, data):
        """Check for embedded files or data within the main file."""
        try:
            # Look for additional file signatures within the data
            signatures = [
                (b'\x89PNG', 'embedded PNG'),
                (b'\xFF\xD8\xFF', 'embedded JPEG'),
                (b'PK\x03\x04', 'embedded ZIP'),
                (b'%PDF', 'embedded PDF'),
                (b'-----BEGIN', 'embedded PEM/key data')
            ]

            for i, (sig, desc) in enumerate(signatures):
                # Look for signature after the first few bytes
                pos = data.find(sig, 100)  # Skip first 100 bytes
                if pos != -1:
                    state.add_insight(f"Found {desc} at offset {pos} in {material.name}", "fileheader_agent")

        except Exception as e:
            logger.error(f"Error checking embedded data: {e}")

    def _extract_strings(self, data, min_length=4):
        """Extract printable strings from binary data."""
        try:
            strings = []
            current_string = ""

            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += chr(byte)
                else:
                    if len(current_string) >= min_length:
                        strings.append(current_string)
                    current_string = ""

            # Don't forget the last string
            if len(current_string) >= min_length:
                strings.append(current_string)

            return strings[:20]  # Return first 20 strings

        except Exception as e:
            logger.error(f"Error extracting strings: {e}")
            return []