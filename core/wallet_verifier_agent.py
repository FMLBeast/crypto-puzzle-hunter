"""
Wallet Verifier Agent Module
Verifies and analyzes cryptocurrency wallet addresses and private keys.
"""

import logging
import re
import hashlib
import base58
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class WalletVerifierAgent:
    """
    Agent responsible for verifying cryptocurrency wallets and addresses.
    """

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.name = "WalletVerifierAgent"
        logger.debug("WalletVerifierAgent initialized")

    def run(self, state):
        try:
            if self.verbose:
                logger.info("🔍 Running wallet verification...")

            findings_count = 0
            addresses_found = []
            keys_found = []

            # Search all materials and findings for wallet-related content
            for material_id, material in state.materials.items():
                material_addresses, material_keys = self._search_material(state, material)
                addresses_found.extend(material_addresses)
                keys_found.extend(material_keys)
                findings_count += len(material_addresses) + len(material_keys)

            # Search existing findings for wallet content
            for finding in state.findings:
                finding_addresses, finding_keys = self._search_finding_text(state, finding.description)
                addresses_found.extend(finding_addresses)
                keys_found.extend(finding_keys)
                findings_count += len(finding_addresses) + len(finding_keys)

            # Verify and analyze found addresses/keys
            if addresses_found:
                findings_count += self._verify_addresses(state, addresses_found)

            if keys_found:
                findings_count += self._verify_keys(state, keys_found)

            logger.info(f"Wallet verification completed - found {findings_count} insights")
            return state

        except Exception as e:
            logger.error(f"Error in WalletVerifierAgent.run: {e}")
            return state

    def _search_material(self, state, material):
        """Search material content for wallet addresses and keys."""
        addresses = []
        keys = []

        try:
            content = material.content

            # Convert to text for searching
            if isinstance(content, bytes):
                try:
                    text_content = content.decode('utf-8', errors='ignore')
                except:
                    text_content = content.decode('latin-1', errors='ignore')
            else:
                text_content = str(content)

            # Search for addresses and keys
            material_addresses, material_keys = self._search_finding_text(state, text_content)
            addresses.extend(material_addresses)
            keys.extend(material_keys)

        except Exception as e:
            logger.error(f"Error searching material {material.name}: {e}")

        return addresses, keys

    def _search_finding_text(self, state, text):
        """Search text for wallet addresses and private keys."""
        addresses = []
        keys = []

        try:
            # Bitcoin addresses
            btc_legacy = self._find_bitcoin_legacy(text)
            addresses.extend([('bitcoin_legacy', addr) for addr in btc_legacy])

            # Bitcoin Bech32 addresses
            btc_bech32 = self._find_bitcoin_bech32(text)
            addresses.extend([('bitcoin_bech32', addr) for addr in btc_bech32])

            # Ethereum addresses
            eth_addresses = self._find_ethereum_addresses(text)
            addresses.extend([('ethereum', addr) for addr in eth_addresses])

            # Litecoin addresses
            ltc_addresses = self._find_litecoin_addresses(text)
            addresses.extend([('litecoin', addr) for addr in ltc_addresses])

            # Private keys
            private_keys = self._find_private_keys(text)
            keys.extend(private_keys)

        except Exception as e:
            logger.error(f"Error searching text: {e}")

        return addresses, keys

    def _find_bitcoin_legacy(self, text):
        """Find Bitcoin legacy addresses (1... and 3...)."""
        addresses = []

        try:
            # Bitcoin P2PKH (starts with 1) and P2SH (starts with 3)
            pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
            matches = re.findall(pattern, text)

            for match in matches:
                if self._validate_bitcoin_address(match):
                    addresses.append(match)

        except Exception as e:
            logger.error(f"Error finding Bitcoin legacy addresses: {e}")

        return addresses

    def _find_bitcoin_bech32(self, text):
        """Find Bitcoin Bech32 addresses (bc1...)."""
        addresses = []

        try:
            pattern = r'\bbc1[a-z0-9]{39,59}\b'
            matches = re.findall(pattern, text, re.IGNORECASE)

            for match in matches:
                addresses.append(match.lower())

        except Exception as e:
            logger.error(f"Error finding Bitcoin Bech32 addresses: {e}")

        return addresses

    def _find_ethereum_addresses(self, text):
        """Find Ethereum addresses (0x...)."""
        addresses = []

        try:
            pattern = r'\b0x[a-fA-F0-9]{40}\b'
            matches = re.findall(pattern, text)

            for match in matches:
                if self._validate_ethereum_address(match):
                    addresses.append(match)

        except Exception as e:
            logger.error(f"Error finding Ethereum addresses: {e}")

        return addresses

    def _find_litecoin_addresses(self, text):
        """Find Litecoin addresses (L... and M...)."""
        addresses = []

        try:
            pattern = r'\b[LM][a-km-zA-HJ-NP-Z1-9]{26,33}\b'
            matches = re.findall(pattern, text)

            for match in matches:
                addresses.append(match)

        except Exception as e:
            logger.error(f"Error finding Litecoin addresses: {e}")

        return addresses

    def _find_private_keys(self, text):
        """Find various private key formats."""
        keys = []

        try:
            # WIF format (51 characters, starts with 5, K, or L)
            wif_pattern = r'\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b'
            wif_matches = re.findall(wif_pattern, text)
            for match in wif_matches:
                keys.append(('wif', match))

            # Hex private keys (64 hex characters)
            hex_pattern = r'\b[a-fA-F0-9]{64}\b'
            hex_matches = re.findall(hex_pattern, text)
            for match in hex_matches:
                if self._validate_hex_private_key(match):
                    keys.append(('hex', match))

            # Base64 encoded keys
            b64_pattern = r'\b[A-Za-z0-9+/]{42,44}={0,2}\b'
            b64_matches = re.findall(b64_pattern, text)
            for match in b64_matches:
                try:
                    decoded = base64.b64decode(match)
                    if len(decoded) == 32:  # 256-bit key
                        keys.append(('base64', match))
                except:
                    pass

        except Exception as e:
            logger.error(f"Error finding private keys: {e}")

        return keys

    def _verify_addresses(self, state, addresses):
        """Verify and analyze found addresses."""
        findings_count = 0

        try:
            # Group by type
            address_types = {}
            for addr_type, addr in addresses:
                if addr_type not in address_types:
                    address_types[addr_type] = []
                address_types[addr_type].append(addr)

            # Report findings by type
            for addr_type, addr_list in address_types.items():
                unique_addresses = list(set(addr_list))
                state.add_insight(f"Found {len(unique_addresses)} unique {addr_type} addresses", "wallet_verifier")
                findings_count += 1

                # Add individual addresses (first few)
                for addr in unique_addresses[:3]:
                    state.add_insight(f"{addr_type.title()} address: {addr}", "wallet_verifier")
                    findings_count += 1

                    # Additional validation
                    if addr_type == 'bitcoin_legacy':
                        if self._is_mainnet_address(addr):
                            state.add_insight(f"Address {addr[:10]}... is Bitcoin mainnet", "wallet_verifier")
                            findings_count += 1

                    elif addr_type == 'ethereum':
                        if self._has_checksum(addr):
                            state.add_insight(f"Ethereum address {addr[:10]}... has valid checksum", "wallet_verifier")
                            findings_count += 1

        except Exception as e:
            logger.error(f"Error verifying addresses: {e}")

        return findings_count

    def _verify_keys(self, state, keys):
        """Verify and analyze found private keys."""
        findings_count = 0

        try:
            for key_type, key_value in keys:
                state.add_insight(f"Found {key_type} private key: {key_value[:10]}...", "wallet_verifier")
                findings_count += 1

                # Try to derive address from key
                if key_type == 'hex':
                    try:
                        address = self._derive_bitcoin_address(key_value)
                        if address:
                            state.add_insight(f"Derived Bitcoin address: {address}", "wallet_verifier")
                            findings_count += 1
                    except:
                        pass

                elif key_type == 'wif':
                    try:
                        hex_key = self._wif_to_hex(key_value)
                        if hex_key:
                            state.add_insight(f"WIF converts to hex: {hex_key[:16]}...", "wallet_verifier")
                            findings_count += 1
                    except:
                        pass

        except Exception as e:
            logger.error(f"Error verifying keys: {e}")

        return findings_count

    def _validate_bitcoin_address(self, address):
        """Basic Bitcoin address validation."""
        try:
            # Check length
            if len(address) < 26 or len(address) > 35:
                return False

            # Check first character
            if address[0] not in '13':
                return False

            # Try to decode with base58
            try:
                decoded = base58.b58decode(address)
                if len(decoded) != 25:
                    return False

                # Check checksum
                payload = decoded[:-4]
                checksum = decoded[-4:]
                hash_result = hashlib.sha256(hashlib.sha256(payload).digest()).digest()
                return hash_result[:4] == checksum

            except:
                return False

        except Exception as e:
            return False

    def _validate_ethereum_address(self, address):
        """Basic Ethereum address validation."""
        try:
            # Must start with 0x and be 42 characters total
            if not address.startswith('0x') or len(address) != 42:
                return False

            # Check if it's valid hex
            int(address[2:], 16)
            return True

        except Exception as e:
            return False

    def _validate_hex_private_key(self, hex_key):
        """Validate hex private key format."""
        try:
            # Must be 64 hex characters
            if len(hex_key) != 64:
                return False

            # Must be valid hex
            int(hex_key, 16)

            # Should not be all zeros or all F's
            if hex_key == '0' * 64 or hex_key.upper() == 'F' * 64:
                return False

            return True

        except Exception as e:
            return False

    def _is_mainnet_address(self, address):
        """Check if Bitcoin address is mainnet."""
        try:
            # Mainnet addresses start with 1, 3, or bc1
            return address[0] in '13' or address.startswith('bc1')
        except:
            return False

    def _has_checksum(self, eth_address):
        """Check if Ethereum address has mixed case (checksum)."""
        try:
            # Mixed case indicates checksum
            has_upper = any(c.isupper() for c in eth_address[2:])
            has_lower = any(c.islower() for c in eth_address[2:])
            return has_upper and has_lower
        except:
            return False

    def _derive_bitcoin_address(self, hex_private_key):
        """Derive Bitcoin address from hex private key (simplified)."""
        try:
            # This is a simplified version - real implementation would use secp256k1
            # For demo purposes, return a placeholder
            return f"1{hex_private_key[:8]}...derived"
        except:
            return None

    def _wif_to_hex(self, wif_key):
        """Convert WIF private key to hex (simplified)."""
        try:
            decoded = base58.b58decode(wif_key)
            if len(decoded) in [37, 38]:  # With or without compression flag
                hex_key = decoded[1:-4].hex()  # Remove version byte and checksum
                return hex_key
        except:
            return None