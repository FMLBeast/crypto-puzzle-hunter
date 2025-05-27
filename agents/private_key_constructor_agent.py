"""
Private Key Constructor Agent Module
Constructs and validates private keys from puzzle findings.
"""

import logging
import re
import hashlib
import base64
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class PrivateKeyConstructorAgent:
    """
    Agent responsible for constructing private keys from puzzle findings.
    """

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.name = "PrivateKeyConstructorAgent"
        logger.debug("PrivateKeyConstructorAgent initialized")

    def run(self, state):
        try:
            if self.verbose:
                logger.info("🔍 Running private key construction...")

            findings_count = 0

            # Analyze all materials for potential key components
            for material_id, material in state.materials.items():
                findings_count += self._search_key_patterns(state, material)

            # Try to construct keys from existing findings
            findings_count += self._construct_from_findings(state)

            logger.info(f"Private key construction completed - found {findings_count} insights")
            return state

        except Exception as e:
            logger.error(f"Error in PrivateKeyConstructorAgent.run: {e}")
            return state

    def _search_key_patterns(self, state, material):
        """Search for private key patterns in material content."""
        findings_count = 0

        try:
            content = material.content
            if isinstance(content, bytes):
                # Try to decode as text
                try:
                    text_content = content.decode('utf-8', errors='ignore')
                except:
                    text_content = content.decode('latin-1', errors='ignore')
            else:
                text_content = str(content)

            # Search for various key formats
            findings_count += self._find_hex_keys(state, material, text_content)
            findings_count += self._find_base64_keys(state, material, text_content)
            findings_count += self._find_pem_keys(state, material, text_content)
            findings_count += self._find_wif_keys(state, material, text_content)
            findings_count += self._find_numeric_sequences(state, material, text_content)

        except Exception as e:
            logger.error(f"Error searching key patterns in {material.name}: {e}")

        return findings_count

    def _find_hex_keys(self, state, material, content):
        """Find hexadecimal private key patterns."""
        findings_count = 0

        try:
            # Look for 64-character hex strings (256-bit keys)
            hex_pattern = r'\b[a-fA-F0-9]{64}\b'
            matches = re.findall(hex_pattern, content)

            for match in matches:
                if self._validate_hex_key(match):
                    state.add_insight(f"Potential 256-bit hex private key found: {match[:16]}...", "private_key_constructor")
                    findings_count += 1

            # Look for 32-character hex strings (128-bit keys)
            hex_pattern_32 = r'\b[a-fA-F0-9]{32}\b'
            matches_32 = re.findall(hex_pattern_32, content)

            for match in matches_32:
                state.add_insight(f"Potential 128-bit hex key component: {match[:16]}...", "private_key_constructor")
                findings_count += 1

        except Exception as e:
            logger.error(f"Error finding hex keys: {e}")

        return findings_count

    def _find_base64_keys(self, state, material, content):
        """Find base64 encoded private keys."""
        findings_count = 0

        try:
            # Look for base64 patterns that could be keys
            base64_pattern = r'\b[A-Za-z0-9+/]{40,}={0,2}\b'
            matches = re.findall(base64_pattern, content)

            for match in matches:
                try:
                    decoded = base64.b64decode(match)
                    if len(decoded) in [16, 32, 48, 64]:  # Common key sizes
                        state.add_insight(f"Potential base64 private key: {match[:20]}... (decoded {len(decoded)} bytes)", "private_key_constructor")
                        findings_count += 1
                except:
                    pass  # Not valid base64

        except Exception as e:
            logger.error(f"Error finding base64 keys: {e}")

        return findings_count

    def _find_pem_keys(self, state, material, content):
        """Find PEM formatted private keys."""
        findings_count = 0

        try:
            # Look for PEM key patterns
            pem_patterns = [
                r'-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----',
                r'-----BEGIN RSA PRIVATE KEY-----.*?-----END RSA PRIVATE KEY-----',
                r'-----BEGIN EC PRIVATE KEY-----.*?-----END EC PRIVATE KEY-----',
                r'-----BEGIN DSA PRIVATE KEY-----.*?-----END DSA PRIVATE KEY-----'
            ]

            for pattern in pem_patterns:
                matches = re.findall(pattern, content, re.DOTALL)
                for match in matches:
                    key_type = "unknown"
                    if "RSA" in match:
                        key_type = "RSA"
                    elif "EC" in match:
                        key_type = "Elliptic Curve"
                    elif "DSA" in match:
                        key_type = "DSA"

                    state.add_insight(f"Found {key_type} PEM private key in {material.name}", "private_key_constructor")
                    findings_count += 1

        except Exception as e:
            logger.error(f"Error finding PEM keys: {e}")

        return findings_count

    def _find_wif_keys(self, state, material, content):
        """Find Wallet Import Format (WIF) Bitcoin private keys."""
        findings_count = 0

        try:
            # WIF keys typically start with 5, K, or L and are base58 encoded
            wif_pattern = r'\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b'
            matches = re.findall(wif_pattern, content)

            for match in matches:
                if self._validate_wif_key(match):
                    state.add_insight(f"Potential Bitcoin WIF private key: {match[:10]}...", "private_key_constructor")
                    findings_count += 1

        except Exception as e:
            logger.error(f"Error finding WIF keys: {e}")

        return findings_count

    def _find_numeric_sequences(self, state, material, content):
        """Find numeric sequences that could be keys."""
        findings_count = 0

        try:
            # Look for long numeric sequences
            numeric_pattern = r'\b\d{20,}\b'
            matches = re.findall(numeric_pattern, content)

            for match in matches:
                if len(match) >= 30:  # Significant length
                    state.add_insight(f"Long numeric sequence (potential key): {len(match)} digits", "private_key_constructor")
                    findings_count += 1

        except Exception as e:
            logger.error(f"Error finding numeric sequences: {e}")

        return findings_count

    def _construct_from_findings(self, state):
        """Try to construct keys from existing findings."""
        findings_count = 0

        try:
            # Look through existing findings for key components
            hex_components = []
            numeric_components = []

            for finding in state.findings:
                text = finding.description.lower()

                # Collect hex patterns from findings
                if 'hex' in text or 'hash' in text:
                    hex_matches = re.findall(r'[a-fA-F0-9]{8,}', finding.description)
                    hex_components.extend(hex_matches)

                # Collect numeric patterns
                if 'number' in text or 'sequence' in text:
                    num_matches = re.findall(r'\d{8,}', finding.description)
                    numeric_components.extend(num_matches)

            # Try to combine components
            if len(hex_components) >= 2:
                combined_hex = ''.join(hex_components)
                if len(combined_hex) >= 32:
                    state.add_insight(f"Combined hex components into potential key: {len(combined_hex)} characters", "private_key_constructor")
                    findings_count += 1

            if len(numeric_components) >= 2:
                combined_numeric = ''.join(numeric_components)
                if len(combined_numeric) >= 20:
                    # Try to convert to hex
                    try:
                        hex_from_numeric = hex(int(combined_numeric))[2:]
                        if len(hex_from_numeric) >= 32:
                            state.add_insight(f"Numeric sequence converts to hex key: {len(hex_from_numeric)} hex chars", "private_key_constructor")
                            findings_count += 1
                    except:
                        pass

        except Exception as e:
            logger.error(f"Error constructing from findings: {e}")

        return findings_count

    def _validate_hex_key(self, hex_string):
        """Basic validation of hex key format."""
        try:
            # Check if it's valid hex
            int(hex_string, 16)

            # Check if it's not all zeros or all F's
            if hex_string == '0' * len(hex_string) or hex_string.upper() == 'F' * len(hex_string):
                return False

            return True
        except:
            return False

    def _validate_wif_key(self, wif_string):
        """Basic validation of WIF key format."""
        try:
            # Basic length and character set check
            if len(wif_string) not in [51, 52]:
                return False

            # Should start with 5, K, or L
            if not wif_string[0] in '5KL':
                return False

            return True
        except:
            return False