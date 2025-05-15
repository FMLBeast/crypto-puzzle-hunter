"""
Crypto Analyzer for CryptoPuzzle-hunter.
Provides advanced cryptographic analysis capabilities beyond classical ciphers.
"""

import hashlib
import base64
import binascii
import re
from typing import Dict, List, Tuple, Optional

from core.state import State
from analyzers.base import register_analyzer, analyzer_compatibility

@register_analyzer("crypto_analyzer")
@analyzer_compatibility(requires_text=True)
def analyze_crypto(state: State) -> State:
    """
    Analyze the puzzle for modern cryptographic elements.
    
    This analyzer focuses on:
    1. Hash identification and cracking attempts
    2. Base64 and other encodings
    3. Modern encryption algorithms
    4. Blockchain-related cryptography
    5. Digital signatures
    
    Args:
        state: Current puzzle state
        
    Returns:
        Updated state with crypto analysis insights
    """
    text = state.puzzle_text
    
    # Skip if no text content
    if not text:
        return state
    
    state.add_insight("Running crypto specialist analysis...", analyzer="crypto_analyzer")
    
    # Check for hashes
    hash_results = identify_hashes(text)
    if hash_results:
        for hash_type, hash_value in hash_results:
            state.add_insight(f"Identified potential {hash_type} hash: {hash_value}", analyzer="crypto_analyzer")
            
            # Try to crack common hashes
            if hash_type in ["MD5", "SHA1", "SHA256"]:
                cracked = attempt_hash_crack(hash_value, hash_type)
                if cracked:
                    state.add_insight(f"Cracked {hash_type} hash {hash_value}: {cracked}", analyzer="crypto_analyzer")
                    state.add_transformation(
                        name=f"{hash_type} hash crack",
                        description=f"Cracked {hash_type} hash to plaintext",
                        input_data=hash_value,
                        output_data=cracked,
                        analyzer="crypto_analyzer"
                    )
    
    # Check for base64 encoded data
    base64_results = identify_and_decode_base64(text)
    if base64_results:
        for original, decoded in base64_results:
            state.add_insight(f"Decoded Base64 data: {original[:20]}... -> {decoded[:30]}...", analyzer="crypto_analyzer")
            state.add_transformation(
                name="Base64 decode",
                description="Decoded Base64 data to plaintext/binary",
                input_data=original,
                output_data=decoded,
                analyzer="crypto_analyzer"
            )
    
    # Check for hex encoded data
    hex_results = identify_and_decode_hex(text)
    if hex_results:
        for original, decoded in hex_results:
            state.add_insight(f"Decoded hex data: {original[:20]}... -> {decoded[:30]}...", analyzer="crypto_analyzer")
            state.add_transformation(
                name="Hex decode",
                description="Decoded hexadecimal data to plaintext/binary",
                input_data=original,
                output_data=decoded,
                analyzer="crypto_analyzer"
            )
    
    # Check for blockchain addresses
    blockchain_addresses = identify_blockchain_addresses(text)
    if blockchain_addresses:
        for addr_type, address in blockchain_addresses:
            state.add_insight(f"Identified {addr_type} address: {address}", analyzer="crypto_analyzer")
    
    # Check for PGP/GPG signatures or keys
    pgp_elements = identify_pgp_elements(text)
    if pgp_elements:
        for elem_type, content in pgp_elements:
            state.add_insight(f"Identified PGP/GPG {elem_type}: {content[:50]}...", analyzer="crypto_analyzer")
    
    return state

def identify_hashes(text: str) -> List[Tuple[str, str]]:
    """
    Identify potential cryptographic hashes in the text.
    
    Args:
        text: Text to analyze
        
    Returns:
        List of (hash_type, hash_value) tuples
    """
    results = []
    
    # Define regex patterns for common hash formats
    hash_patterns = {
        "MD5": r"\b[a-fA-F0-9]{32}\b",
        "SHA1": r"\b[a-fA-F0-9]{40}\b",
        "SHA256": r"\b[a-fA-F0-9]{64}\b",
        "SHA512": r"\b[a-fA-F0-9]{128}\b"
    }
    
    # Search for each hash pattern
    for hash_type, pattern in hash_patterns.items():
        matches = re.findall(pattern, text)
        for match in matches:
            # Verify it's not just a random hex string by checking entropy
            if is_likely_hash(match):
                results.append((hash_type, match))
    
    return results

def is_likely_hash(hex_string: str) -> bool:
    """
    Check if a hex string is likely to be a hash by analyzing its entropy.
    
    Args:
        hex_string: Hexadecimal string to check
        
    Returns:
        True if the string is likely a hash, False otherwise
    """
    # Simple entropy check - real hashes have fairly uniform distribution
    char_counts = {}
    for char in hex_string.lower():
        char_counts[char] = char_counts.get(char, 0) + 1
    
    # Calculate normalized entropy
    entropy = 0
    length = len(hex_string)
    for count in char_counts.values():
        probability = count / length
        entropy -= probability * (probability.bit_length() if probability > 0 else 0)
    
    # Higher entropy suggests more randomness, typical of hashes
    return entropy > 0.6

def attempt_hash_crack(hash_value: str, hash_type: str) -> Optional[str]:
    """
    Attempt to crack a hash using a small dictionary of common values.
    
    Args:
        hash_value: The hash to crack
        hash_type: Type of hash (MD5, SHA1, SHA256)
        
    Returns:
        Cracked plaintext if successful, None otherwise
    """
    # Common passwords and phrases to try
    common_values = [
        "password", "123456", "admin", "welcome", "secret",
        "letmein", "monkey", "1234567890", "qwerty",
        "abc123", "password123", "admin123", "test",
        "cryptopuzzle", "hunter", "puzzle", "crypto",
        "flag", "key", "solution", "answer", "treasure",
        "bitcoin", "ethereum", "blockchain", "satoshi"
    ]
    
    hash_function = None
    if hash_type == "MD5":
        hash_function = lambda x: hashlib.md5(x.encode()).hexdigest()
    elif hash_type == "SHA1":
        hash_function = lambda x: hashlib.sha1(x.encode()).hexdigest()
    elif hash_type == "SHA256":
        hash_function = lambda x: hashlib.sha256(x.encode()).hexdigest()
    else:
        return None
    
    # Try each common value
    for value in common_values:
        if hash_function(value) == hash_value.lower():
            return value
    
    return None

def identify_and_decode_base64(text: str) -> List[Tuple[str, str]]:
    """
    Identify and decode potential Base64 encoded strings.
    
    Args:
        text: Text to analyze
        
    Returns:
        List of (original, decoded) tuples
    """
    results = []
    
    # Find potential base64 strings (must be at least 16 chars to reduce false positives)
    base64_pattern = r'[A-Za-z0-9+/]{16,}={0,2}'
    matches = re.findall(base64_pattern, text)
    
    for match in matches:
        try:
            # Try to decode and check if result is printable or looks like binary data
            decoded = base64.b64decode(match).decode('utf-8', errors='replace')
            if any(c.isprintable() for c in decoded):
                results.append((match, decoded))
        except Exception:
            # If decoding as text fails, it might be binary data
            try:
                decoded_bytes = base64.b64decode(match)
                # Convert to hex representation for display
                hex_repr = binascii.hexlify(decoded_bytes).decode('ascii')
                results.append((match, f"[Binary data, hex: {hex_repr[:30]}...]"))
            except Exception:
                # Not valid base64
                pass
    
    return results

def identify_and_decode_hex(text: str) -> List[Tuple[str, str]]:
    """
    Identify and decode potential hexadecimal encoded strings.
    
    Args:
        text: Text to analyze
        
    Returns:
        List of (original, decoded) tuples
    """
    results = []
    
    # Find potential hex strings (must be even length and at least 8 chars)
    hex_pattern = r'\b(?:[0-9A-Fa-f]{2}){4,}\b'
    matches = re.findall(hex_pattern, text)
    
    for match in matches:
        if len(match) % 2 == 0:  # Valid hex strings have even length
            try:
                # Try to decode and check if result is printable
                decoded_bytes = binascii.unhexlify(match)
                try:
                    decoded = decoded_bytes.decode('utf-8', errors='replace')
                    if any(c.isprintable() for c in decoded):
                        results.append((match, decoded))
                except UnicodeDecodeError:
                    # If decoding as text fails, it's binary data
                    results.append((match, f"[Binary data, length: {len(decoded_bytes)} bytes]"))
            except binascii.Error:
                # Not valid hex
                pass
    
    return results

def identify_blockchain_addresses(text: str) -> List[Tuple[str, str]]:
    """
    Identify potential blockchain addresses in the text.
    
    Args:
        text: Text to analyze
        
    Returns:
        List of (address_type, address) tuples
    """
    results = []
    
    # Bitcoin address patterns
    btc_pattern = r'\b(1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,39}\b'
    btc_matches = re.findall(btc_pattern, text)
    for match in btc_matches:
        results.append(("Bitcoin", match))
    
    # Ethereum address pattern
    eth_pattern = r'\b0x[a-fA-F0-9]{40}\b'
    eth_matches = re.findall(eth_pattern, text)
    for match in eth_matches:
        results.append(("Ethereum", match))
    
    return results

def identify_pgp_elements(text: str) -> List[Tuple[str, str]]:
    """
    Identify PGP/GPG elements like signatures, keys, or encrypted messages.
    
    Args:
        text: Text to analyze
        
    Returns:
        List of (element_type, content) tuples
    """
    results = []
    
    # PGP public key block
    if "-----BEGIN PGP PUBLIC KEY BLOCK-----" in text:
        pgp_key_pattern = r'-----BEGIN PGP PUBLIC KEY BLOCK-----(.*?)-----END PGP PUBLIC KEY BLOCK-----'
        matches = re.findall(pgp_key_pattern, text, re.DOTALL)
        for match in matches:
            full_match = f"-----BEGIN PGP PUBLIC KEY BLOCK-----{match}-----END PGP PUBLIC KEY BLOCK-----"
            results.append(("public key", full_match))
    
    # PGP signature
    if "-----BEGIN PGP SIGNATURE-----" in text:
        pgp_sig_pattern = r'-----BEGIN PGP SIGNATURE-----(.*?)-----END PGP SIGNATURE-----'
        matches = re.findall(pgp_sig_pattern, text, re.DOTALL)
        for match in matches:
            full_match = f"-----BEGIN PGP SIGNATURE-----{match}-----END PGP SIGNATURE-----"
            results.append(("signature", full_match))
    
    # PGP message
    if "-----BEGIN PGP MESSAGE-----" in text:
        pgp_msg_pattern = r'-----BEGIN PGP MESSAGE-----(.*?)-----END PGP MESSAGE-----'
        matches = re.findall(pgp_msg_pattern, text, re.DOTALL)
        for match in matches:
            full_match = f"-----BEGIN PGP MESSAGE-----{match}-----END PGP MESSAGE-----"
            results.append(("encrypted message", full_match))
    
    return results