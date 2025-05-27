"""
PGP Agent Module
Handles PGP/GPG encryption, decryption, and key analysis for crypto puzzles.
"""

import logging
import re
import base64
import binascii
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class PGPAgent:
    """
    Agent responsible for PGP/GPG operations and analysis.
    """

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.name = "PGPAgent"
        logger.debug("PGPAgent initialized")

    def run(self, state):
        try:
            if self.verbose:
                logger.info("🔍 Running PGP analysis...")

            findings_count = 0

            # Analyze all materials for PGP content
            for material_id, material in state.materials.items():
                findings_count += self._analyze_material(state, material)

            # Analyze existing findings for PGP content
            findings_count += self._analyze_findings(state)

            logger.info(f"PGP analysis completed - found {findings_count} insights")
            return state

        except Exception as e:
            logger.error(f"Error in PGPAgent.run: {e}")
            return state

    def _analyze_material(self, state, material):
        """Analyze material for PGP-related content."""
        findings_count = 0

        try:
            content = material.content

            # Handle different content types
            if isinstance(content, bytes):
                findings_count += self._analyze_binary_pgp(state, material, content)

                # Try to decode as text for PGP analysis
                try:
                    text_content = content.decode('utf-8', errors='ignore')
                    findings_count += self._analyze_text_pgp(state, material, text_content)
                except:
                    try:
                        text_content = content.decode('ascii', errors='ignore')
                        findings_count += self._analyze_text_pgp(state, material, text_content)
                    except:
                        pass
            else:
                text_content = str(content)
                findings_count += self._analyze_text_pgp(state, material, text_content)

        except Exception as e:
            logger.error(f"Error analyzing material {material.name}: {e}")

        return findings_count

    def _analyze_binary_pgp(self, state, material, data):
        """Analyze binary data for PGP content."""
        findings_count = 0

        try:
            # Look for PGP binary signatures
            if data.startswith(b'\x99\x01'):  # Common PGP packet header
                state.add_insight(f"{material.name} contains binary PGP data", "pgp_agent")
                findings_count += 1
                findings_count += self._analyze_pgp_packets(state, material, data)

            # Look for ASCII-armored PGP in binary data
            text_data = data.decode('ascii', errors='ignore')
            if '-----BEGIN PGP' in text_data:
                state.add_insight(f"{material.name} contains ASCII-armored PGP data", "pgp_agent")
                findings_count += 1
                findings_count += self._analyze_text_pgp(state, material, text_data)

        except Exception as e:
            logger.error(f"Error analyzing binary PGP: {e}")

        return findings_count

    def _analyze_text_pgp(self, state, material, text):
        """Analyze text content for PGP data."""
        findings_count = 0

        try:
            # Find PGP blocks
            pgp_blocks = self._find_pgp_blocks(text)

            for block_type, block_content in pgp_blocks:
                state.add_insight(f"Found PGP {block_type} in {material.name}", "pgp_agent")
                findings_count += 1

                findings_count += self._analyze_pgp_block(state, block_type, block_content)

        except Exception as e:
            logger.error(f"Error analyzing text PGP: {e}")

        return findings_count

    def _find_pgp_blocks(self, text):
        """Find PGP blocks in text."""
        blocks = []

        try:
            # PGP block patterns
            patterns = [
                (r'-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----', 'PUBLIC KEY'),
                (r'-----BEGIN PGP PRIVATE KEY BLOCK-----.*?-----END PGP PRIVATE KEY BLOCK-----', 'PRIVATE KEY'),
                (r'-----BEGIN PGP MESSAGE-----.*?-----END PGP MESSAGE-----', 'MESSAGE'),
                (r'-----BEGIN PGP SIGNATURE-----.*?-----END PGP SIGNATURE-----', 'SIGNATURE'),
                (r'-----BEGIN PGP SIGNED MESSAGE-----.*?-----END PGP SIGNATURE-----', 'SIGNED MESSAGE'),
            ]

            for pattern, block_type in patterns:
                matches = re.findall(pattern, text, re.DOTALL | re.IGNORECASE)
                for match in matches:
                    blocks.append((block_type, match))

        except Exception as e:
            logger.error(f"Error finding PGP blocks: {e}")

        return blocks

    def _analyze_pgp_block(self, state, block_type, block_content):
        """Analyze a specific PGP block."""
        findings_count = 0

        try:
            # Extract the base64 content
            lines = block_content.split('\n')
            base64_lines = []

            for line in lines:
                line = line.strip()
                if line and not line.startswith('-----') and not line.startswith('Hash:') and not line.startswith('Version:'):
                    base64_lines.append(line)

            if base64_lines:
                base64_content = ''.join(base64_lines)

                try:
                    # Decode base64 content
                    decoded_data = base64.b64decode(base64_content)
                    state.add_insight(f"PGP {block_type} contains {len(decoded_data)} bytes of data", "pgp_agent")
                    findings_count += 1

                    # Analyze the decoded PGP data
                    findings_count += self._analyze_pgp_packets(state, None, decoded_data)

                except Exception as e:
                    logger.debug(f"Could not decode PGP base64: {e}")

            # Look for key IDs or fingerprints in comments
            if 'Key ID' in block_content or 'Fingerprint' in block_content:
                key_info = re.findall(r'Key ID[:\s]+([A-Fa-f0-9]+)', block_content)
                fingerprints = re.findall(r'Fingerprint[:\s]+([A-Fa-f0-9\s]+)', block_content)

                for key_id in key_info:
                    state.add_insight(f"PGP Key ID found: {key_id}", "pgp_agent")
                    findings_count += 1

                for fingerprint in fingerprints:
                    clean_fp = re.sub(r'\s+', '', fingerprint)
                    state.add_insight(f"PGP Fingerprint found: {clean_fp[:20]}...", "pgp_agent")
                    findings_count += 1

            # Special analysis for different block types
            if block_type == 'PRIVATE KEY':
                state.add_insight("Found PGP private key - potentially valuable!", "pgp_agent")
                findings_count += 1

            elif block_type == 'MESSAGE':
                state.add_insight("Found encrypted PGP message - may contain puzzle solution", "pgp_agent")
                findings_count += 1

            elif block_type == 'SIGNED MESSAGE':
                # Extract the signed content
                signed_content = self._extract_signed_content(block_content)
                if signed_content:
                    state.add_insight(f"PGP signed message content: {signed_content[:100]}...", "pgp_agent")
                    findings_count += 1

        except Exception as e:
            logger.error(f"Error analyzing PGP block: {e}")

        return findings_count

    def _analyze_pgp_packets(self, state, material, data):
        """Analyze PGP packet structure."""
        findings_count = 0

        try:
            pos = 0
            packet_count = 0

            while pos < len(data) - 2 and packet_count < 10:  # Limit to avoid infinite loops
                # Try to parse PGP packet header
                if data[pos] & 0x80:  # New format packet
                    packet_tag = (data[pos] & 0x3F)
                    pos += 1

                    if packet_tag == 1:
                        packet_type = "Public Key Encrypted Session Key"
                    elif packet_tag == 2:
                        packet_type = "Signature"
                    elif packet_tag == 6:
                        packet_type = "Public Key"
                    elif packet_tag == 5:
                        packet_type = "Secret Key"
                    elif packet_tag == 8:
                        packet_type = "Compressed Data"
                    elif packet_tag == 9:
                        packet_type = "Symmetrically Encrypted Data"
                    elif packet_tag == 11:
                        packet_type = "Literal Data"
                    else:
                        packet_type = f"Unknown ({packet_tag})"

                    state.add_insight(f"PGP packet found: {packet_type}", "pgp_agent")
                    findings_count += 1
                    packet_count += 1

                    # Try to get packet length and skip to next packet
                    if pos < len(data):
                        length_type = data[pos] & 0x03
                        if length_type == 0:  # 1-byte length
                            if pos + 1 < len(data):
                                packet_length = data[pos + 1]
                                pos += 2 + packet_length
                        elif length_type == 1:  # 2-byte length
                            if pos + 2 < len(data):
                                packet_length = (data[pos + 1] << 8) | data[pos + 2]
                                pos += 3 + packet_length
                        else:
                            break  # Variable length or unknown
                    else:
                        break
                else:
                    break

        except Exception as e:
            logger.debug(f"Error analyzing PGP packets: {e}")

        return findings_count

    def _extract_signed_content(self, signed_message):
        """Extract the signed content from a PGP signed message."""
        try:
            lines = signed_message.split('\n')
            content_lines = []
            in_content = False

            for line in lines:
                if line.strip() == '-----BEGIN PGP SIGNED MESSAGE-----':
                    in_content = True
                    continue
                elif line.strip().startswith('-----BEGIN PGP SIGNATURE-----'):
                    break
                elif in_content and not line.startswith('Hash:'):
                    content_lines.append(line)

            return '\n'.join(content_lines).strip()

        except Exception as e:
            logger.error(f"Error extracting signed content: {e}")
            return None

    def _analyze_findings(self, state):
        """Analyze existing findings for PGP content."""
        findings_count = 0

        try:
            for finding in state.findings:
                text = finding.description

                # Look for PGP-related keywords in findings
                if any(keyword in text.lower() for keyword in ['pgp', 'gpg', 'encrypt', 'decrypt', 'signature', 'key']):
                    # Check if this finding contains actual PGP data
                    if '-----BEGIN PGP' in text:
                        pgp_blocks = self._find_pgp_blocks(text)
                        if pgp_blocks:
                            state.add_insight(f"Found PGP data in existing finding: {finding.title}", "pgp_agent")
                            findings_count += 1

                            for block_type, block_content in pgp_blocks:
                                findings_count += self._analyze_pgp_block(state, block_type, block_content)

                # Look for key IDs or fingerprints in findings
                key_ids = re.findall(r'\b[A-Fa-f0-9]{8,40}\b', text)
                for key_id in key_ids:
                    if len(key_id) in [8, 16, 40]:  # Common PGP key ID lengths
                        state.add_insight(f"Potential PGP Key ID in findings: {key_id}", "pgp_agent")
                        findings_count += 1

        except Exception as e:
            logger.error(f"Error analyzing findings for PGP: {e}")

        return findings_count

    def _attempt_decryption(self, state, encrypted_data, possible_keys):
        """Attempt to decrypt PGP data with possible keys (placeholder)."""
        findings_count = 0

        try:
            # This would require a full PGP implementation
            # For now, just report the attempt
            if possible_keys:
                state.add_insight(f"Could attempt PGP decryption with {len(possible_keys)} possible keys", "pgp_agent")
                findings_count += 1

        except Exception as e:
            logger.error(f"Error in PGP decryption attempt: {e}")

        return findings_count

    def _validate_pgp_data(self, data):
        """Validate if data looks like valid PGP content."""
        try:
            # Check for PGP ASCII armor
            if isinstance(data, str):
                return '-----BEGIN PGP' in data and '-----END PGP' in data

            # Check for binary PGP packet headers
            elif isinstance(data, bytes):
                return len(data) > 0 and (data[0] & 0x80) != 0  # PGP packet tag

        except Exception as e:
            logger.error(f"Error validating PGP data: {e}")

        return False