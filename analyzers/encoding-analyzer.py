"""
Encoding analyzer module for Crypto Hunter

This module provides functions for detecting and decoding
various encoding schemes like Base64, Hex, ASCII85, etc.
"""
import logging
import re
import binascii
import base64
import string
import unicodedata
from typing import Dict, List, Any, Optional, Tuple, Union

from core.state import State
from analyzers.base import register_analyzer, analyzer_compatibility

logger = logging.getLogger(__name__)


@register_analyzer("encoding_analyze")
@analyzer_compatibility(requires_text=True)
def analyze_encoding(state: State) -> State:
    """
    Main encoding analyzer function that detects and decodes various encodings.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_text:
        state.add_insight("No text data available for encoding analysis", analyzer="encoding_analyzer")
        return state
    
    # Run various encoding analysis functions
    state = detect_and_decode_base64(state)
    state = detect_and_decode_hex(state)
    state = detect_and_decode_ascii85(state)
    state = detect_and_decode_binary(state)
    state = detect_and_decode_url(state)
    state = detect_and_decode_rot(state)
    state = detect_and_decode_custom(state)
    
    return state


@register_analyzer("detect_and_decode_base64")
@analyzer_compatibility(requires_text=True)
def detect_and_decode_base64(state: State) -> State:
    """
    Detect and decode Base64 encoding.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_text:
        return state
    
    text = state.puzzle_text.strip()
    
    # Only process if text looks like base64
    if not is_likely_base64(text):
        return state
    
    try:
        # Try standard Base64
        decoded = base64.b64decode(text)
        
        # Check if decoded data is text or binary
        if is_printable_text(decoded):
            # It's text, decode to string
            decoded_text = decoded.decode('utf-8', errors='replace')
            state.add_insight(
                "Text appears to be Base64 encoded",
                analyzer="encoding_analyzer",
                confidence=0.9
            )
            state.add_transformation(
                name="base64_decode",
                description="Decoded Base64 to text",
                input_data=text,
                output_data=decoded_text,
                analyzer="encoding_analyzer"
            )
            
            # Update puzzle text with decoded data for further analysis
            state.puzzle_text = decoded_text
        else:
            # It's binary data
            state.add_insight(
                "Text appears to be Base64 encoded binary data",
                analyzer="encoding_analyzer",
                confidence=0.8
            )
            state.add_transformation(
                name="base64_decode_binary",
                description="Decoded Base64 to binary data",
                input_data=text,
                output_data=decoded,
                analyzer="encoding_analyzer"
            )
            
            # Store decoded binary data for further analysis
            if not state.puzzle_data:
                state.puzzle_data = decoded
    
    except Exception as e:
        # Try with URL-safe Base64
        try:
            decoded = base64.urlsafe_b64decode(text)
            
            if is_printable_text(decoded):
                decoded_text = decoded.decode('utf-8', errors='replace')
                state.add_insight(
                    "Text appears to be URL-safe Base64 encoded",
                    analyzer="encoding_analyzer",
                    confidence=0.8
                )
                state.add_transformation(
                    name="urlsafe_base64_decode",
                    description="Decoded URL-safe Base64 to text",
                    input_data=text,
                    output_data=decoded_text,
                    analyzer="encoding_analyzer"
                )
                
                # Update puzzle text with decoded data
                state.puzzle_text = decoded_text
            else:
                state.add_insight(
                    "Text appears to be URL-safe Base64 encoded binary data",
                    analyzer="encoding_analyzer",
                    confidence=0.7
                )
                state.add_transformation(
                    name="urlsafe_base64_decode_binary",
                    description="Decoded URL-safe Base64 to binary data",
                    input_data=text,
                    output_data=decoded,
                    analyzer="encoding_analyzer"
                )
                
                if not state.puzzle_data:
                    state.puzzle_data = decoded
        
        except Exception as e2:
            # Check for Base64 with padding issues
            if is_likely_base64(text, check_padding=False):
                # Try to fix padding
                padded_text = fix_base64_padding(text)
                
                try:
                    decoded = base64.b64decode(padded_text)
                    
                    if is_printable_text(decoded):
                        decoded_text = decoded.decode('utf-8', errors='replace')
                        state.add_insight(
                            "Text appears to be Base64 encoded with incorrect padding",
                            analyzer="encoding_analyzer",
                            confidence=0.7
                        )
                        state.add_transformation(
                            name="base64_decode_fixed_padding",
                            description="Fixed padding and decoded Base64 to text",
                            input_data=text,
                            output_data=decoded_text,
                            analyzer="encoding_analyzer"
                        )
                        
                        # Update puzzle text with decoded data
                        state.puzzle_text = decoded_text
                    else:
                        state.add_insight(
                            "Text appears to be Base64 encoded binary data with incorrect padding",
                            analyzer="encoding_analyzer",
                            confidence=0.6
                        )
                        state.add_transformation(
                            name="base64_decode_binary_fixed_padding",
                            description="Fixed padding and decoded Base64 to binary data",
                            input_data=text,
                            output_data=decoded,
                            analyzer="encoding_analyzer"
                        )
                        
                        if not state.puzzle_data:
                            state.puzzle_data = decoded
                
                except Exception as e3:
                    pass
    
    return state


@register_analyzer("detect_and_decode_hex")
@analyzer_compatibility(requires_text=True)
def detect_and_decode_hex(state: State) -> State:
    """
    Detect and decode hexadecimal encoding.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_text:
        return state
    
    text = state.puzzle_text.strip()
    
    # Only process if text looks like hex
    if not is_likely_hex(text):
        return state
    
    try:
        # Remove any whitespace, '0x' prefix, or delimiters
        clean_text = re.sub(r'[\s:,]', '', text)
        if clean_text.lower().startswith('0x'):
            clean_text = clean_text[2:]
        
        # Ensure we have an even number of characters
        if len(clean_text) % 2 != 0:
            clean_text = '0' + clean_text
        
        # Decode hex
        decoded = bytes.fromhex(clean_text)
        
        # Check if decoded data is text or binary
        if is_printable_text(decoded):
            decoded_text = decoded.decode('utf-8', errors='replace')
            state.add_insight(
                "Text appears to be hex encoded",
                analyzer="encoding_analyzer",
                confidence=0.9
            )
            state.add_transformation(
                name="hex_decode",
                description="Decoded hex to text",
                input_data=text,
                output_data=decoded_text,
                analyzer="encoding_analyzer"
            )
            
            # Update puzzle text with decoded data
            state.puzzle_text = decoded_text
        else:
            state.add_insight(
                "Text appears to be hex encoded binary data",
                analyzer="encoding_analyzer",
                confidence=0.8
            )
            state.add_transformation(
                name="hex_decode_binary",
                description="Decoded hex to binary data",
                input_data=text,
                output_data=decoded,
                analyzer="encoding_analyzer"
            )
            
            if not state.puzzle_data:
                state.puzzle_data = decoded
    
    except Exception as e:
        # Try with lenient hex parsing (ignore non-hex chars)
        try:
            hex_chars = ''.join(c for c in text if c in string.hexdigits)
            if len(hex_chars) % 2 != 0:
                hex_chars = '0' + hex_chars
            
            if len(hex_chars) >= 4:  # Minimum 2 bytes
                decoded = bytes.fromhex(hex_chars)
                
                if is_printable_text(decoded):
                    decoded_text = decoded.decode('utf-8', errors='replace')
                    state.add_insight(
                        "Text contains hex encoded data with non-hex characters",
                        analyzer="encoding_analyzer",
                        confidence=0.6
                    )
                    state.add_transformation(
                        name="lenient_hex_decode",
                        description="Extracted and decoded hex to text",
                        input_data=text,
                        output_data=decoded_text,
                        analyzer="encoding_analyzer"
                    )
                else:
                    state.add_insight(
                        "Text contains hex encoded binary data with non-hex characters",
                        analyzer="encoding_analyzer",
                        confidence=0.5
                    )
                    state.add_transformation(
                        name="lenient_hex_decode_binary",
                        description="Extracted and decoded hex to binary data",
                        input_data=text,
                        output_data=decoded,
                        analyzer="encoding_analyzer"
                    )
        
        except Exception as e2:
            pass
    
    return state


@register_analyzer("detect_and_decode_ascii85")
@analyzer_compatibility(requires_text=True)
def detect_and_decode_ascii85(state: State) -> State:
    """
    Detect and decode ASCII85/Base85 encoding.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_text:
        return state
    
    text = state.puzzle_text.strip()
    
    # Check if it might be ASCII85/Base85
    if not is_likely_ascii85(text):
        return state
    
    # Try different ASCII85 variants
    for name, func, wrapper in [
        ("ASCII85", base64.a85decode, None),
        ("Adobe ASCII85", base64.a85decode, lambda t: t.startswith('<~') and t.endswith('~>'), lambda t: t[2:-2]),
        ("btoa", base64.a85decode, None),
        ("Base85 (RFC 1924)", base64.b85decode, None)
    ]:
        try:
            decode_text = text
            
            # Apply wrapper if needed
            if wrapper:
                check_func, transform_func = wrapper
                if check_func and not check_func(text):
                    continue
                decode_text = transform_func(text)
            
            # Decode
            decoded = func(decode_text)
            
            # Check if decoded data is text
            if is_printable_text(decoded):
                decoded_text = decoded.decode('utf-8', errors='replace')
                state.add_insight(
                    f"Text appears to be {name} encoded",
                    analyzer="encoding_analyzer",
                    confidence=0.8
                )
                state.add_transformation(
                    name=f"{name.lower().replace(' ', '_')}_decode",
                    description=f"Decoded {name} to text",
                    input_data=text,
                    output_data=decoded_text,
                    analyzer="encoding_analyzer"
                )
                
                # Update puzzle text with decoded data
                state.puzzle_text = decoded_text
                break
            else:
                state.add_insight(
                    f"Text appears to be {name} encoded binary data",
                    analyzer="encoding_analyzer",
                    confidence=0.7
                )
                state.add_transformation(
                    name=f"{name.lower().replace(' ', '_')}_decode_binary",
                    description=f"Decoded {name} to binary data",
                    input_data=text,
                    output_data=decoded,
                    analyzer="encoding_analyzer"
                )
                
                if not state.puzzle_data:
                    state.puzzle_data = decoded
                break
        
        except Exception as e:
            continue
    
    return state


@register_analyzer("detect_and_decode_binary")
@analyzer_compatibility(requires_text=True)
def detect_and_decode_binary(state: State) -> State:
    """
    Detect and decode binary encoding (e.g., "01010101").

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_text:
        return state
    
    text = state.puzzle_text.strip()
    
    # Check if it looks like binary data
    if not is_likely_binary(text):
        return state
    
    try:
        # Remove whitespace
        clean_text = re.sub(r'\s', '', text)
        
        # Check if it's a valid binary string
        if not all(bit in '01' for bit in clean_text):
            return state
        
        # Pad to multiple of 8 if needed
        padding = 8 - (len(clean_text) % 8) if len(clean_text) % 8 != 0 else 0
        padded_binary = '0' * padding + clean_text
        
        # Convert binary to bytes
        decoded = bytes(int(padded_binary[i:i+8], 2) for i in range(0, len(padded_binary), 8))
        
        # Check if decoded data is text
        if is_printable_text(decoded):
            decoded_text = decoded.decode('utf-8', errors='replace')
            state.add_insight(
                "Text appears to be binary encoded",
                analyzer="encoding_analyzer",
                confidence=0.9
            )
            state.add_transformation(
                name="binary_decode",
                description="Decoded binary to text",
                input_data=text,
                output_data=decoded_text,
                analyzer="encoding_analyzer"
            )
            
            # Update puzzle text with decoded data
            state.puzzle_text = decoded_text
        else:
            state.add_insight(
                "Text appears to be binary encoded data",
                analyzer="encoding_analyzer",
                confidence=0.8
            )
            state.add_transformation(
                name="binary_decode_binary",
                description="Decoded binary to binary data",
                input_data=text,
                output_data=decoded,
                analyzer="encoding_analyzer"
            )
            
            if not state.puzzle_data:
                state.puzzle_data = decoded
    
    except Exception as e:
        # Try binary with word-like grouping
        try:
            # Split by whitespace
            binary_words = text.split()
            
            # Check if all words are binary
            if all(re.match(r'^[01]+$', word) for word in binary_words):
                # Convert each binary word to ASCII
                chars = []
                for word in binary_words:
                    try:
                        byte_val = int(word, 2)
                        if 0 <= byte_val <= 255:
                            chars.append(chr(byte_val))
                    except:
                        pass
                
                if chars:
                    decoded_text = ''.join(chars)
                    state.add_insight(
                        "Text appears to be word-grouped binary encoded ASCII",
                        analyzer="encoding_analyzer",
                        confidence=0.7
                    )
                    state.add_transformation(
                        name="binary_word_decode",
                        description="Decoded word-grouped binary to text",
                        input_data=text,
                        output_data=decoded_text,
                        analyzer="encoding_analyzer"
                    )
                    
                    # Update puzzle text with decoded data
                    state.puzzle_text = decoded_text
        
        except Exception as e2:
            pass
    
    return state


@register_analyzer("detect_and_decode_url")
@analyzer_compatibility(requires_text=True)
def detect_and_decode_url(state: State) -> State:
    """
    Detect and decode URL encoding.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_text:
        return state
    
    text = state.puzzle_text.strip()
    
    # Check if it might be URL encoded
    if '%' not in text:
        return state
    
    # Check for URL encoding pattern
    if not re.search(r'%[0-9A-Fa-f]{2}', text):
        return state
    
    try:
        import urllib.parse
        decoded = urllib.parse.unquote(text)
        
        # Check if the decoded text is different from the original
        if decoded != text:
            state.add_insight(
                "Text appears to be URL encoded",
                analyzer="encoding_analyzer",
                confidence=0.9
            )
            state.add_transformation(
                name="url_decode",
                description="Decoded URL encoding",
                input_data=text,
                output_data=decoded,
                analyzer="encoding_analyzer"
            )
            
            # Update puzzle text with decoded data
            state.puzzle_text = decoded
    
    except Exception as e:
        pass
    
    return state


@register_analyzer("detect_and_decode_rot")
@analyzer_compatibility(requires_text=True)
def detect_and_decode_rot(state: State) -> State:
    """
    Detect and decode ROT encoding (like ROT13).

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_text:
        return state
    
    text = state.puzzle_text.strip()
    
    # Skip if text is too short or has too many non-alphabetic characters
    if len(text) < 4:
        return state
    
    # Count alphabetic characters
    alpha_count = sum(c.isalpha() for c in text)
    if alpha_count / len(text) < 0.5:
        return state
    
    # Try different ROT values
    best_score = 0
    best_rot = 0
    best_decoded = ""
    
    for rot in range(1, 26):
        decoded = apply_rot(text, rot)
        score = score_english_text(decoded)
        
        if score > best_score:
            best_score = score
            best_rot = rot
            best_decoded = decoded
    
    # If we found a good ROT value
    if best_score > 0.5:
        rot_name = "ROT13" if best_rot == 13 else f"ROT{best_rot}"
        state.add_insight(
            f"Text appears to be {rot_name} encoded",
            analyzer="encoding_analyzer",
            confidence=min(best_score, 0.9)
        )
        state.add_transformation(
            name=f"{rot_name.lower()}_decode",
            description=f"Decoded {rot_name} to text",
            input_data=text,
            output_data=best_decoded,
            analyzer="encoding_analyzer"
        )
        
        # Update puzzle text with decoded data
        state.puzzle_text = best_decoded
    
    return state


@register_analyzer("detect_and_decode_custom")
@analyzer_compatibility(requires_text=True)
def detect_and_decode_custom(state: State) -> State:
    """
    Detect and decode custom or uncommon encodings.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_text:
        return state
    
    text = state.puzzle_text.strip()
    
    # Try decoding Bacon cipher
    if is_likely_bacon_cipher(text):
        decoded = decode_bacon_cipher(text)
        if decoded:
            state.add_insight(
                "Text might be encoded with Bacon cipher",
                analyzer="encoding_analyzer",
                confidence=0.7
            )
            state.add_transformation(
                name="bacon_cipher_decode",
                description="Decoded Bacon cipher to text",
                input_data=text,
                output_data=decoded,
                analyzer="encoding_analyzer"
            )
            
            # Update puzzle text with decoded data
            state.puzzle_text = decoded
    
    # Try decoding Morse code
    if is_likely_morse_code(text):
        decoded = decode_morse_code(text)
        if decoded:
            state.add_insight(
                "Text might be encoded in Morse code",
                analyzer="encoding_analyzer",
                confidence=0.8
            )
            state.add_transformation(
                name="morse_code_decode",
                description="Decoded Morse code to text",
                input_data=text,
                output_data=decoded,
                analyzer="encoding_analyzer"
            )
            
            # Update puzzle text with decoded data
            state.puzzle_text = decoded
    
    # Try decoding NATO phonetic alphabet
    if is_likely_nato_phonetic(text):
        decoded = decode_nato_phonetic(text)
        if decoded:
            state.add_insight(
                "Text might be encoded with NATO phonetic alphabet",
                analyzer="encoding_analyzer",
                confidence=0.6
            )
            state.add_transformation(
                name="nato_phonetic_decode",
                description="Decoded NATO phonetic alphabet to text",
                input_data=text,
                output_data=decoded,
                analyzer="encoding_analyzer"
            )
            
            # Update puzzle text with decoded data
            state.puzzle_text = decoded
    
    return state


# Helper functions

def is_likely_base64(text: str, check_padding: bool = True) -> bool:
    """
    Check if a string is likely Base64 encoded.
    
    Args:
        text: Text to check
        check_padding: Whether to check for valid padding
        
    Returns:
        True if likely Base64, False otherwise
    """
    # Remove whitespace
    text = text.strip()
    
    # Check length - must be a multiple of 4 if padding is present
    if check_padding and len(text) % 4 != 0:
        return False
    
    # Check alphabet
    base64_chars = set(string.ascii_letters + string.digits + '+/=')
    url_safe_chars = set(string.ascii_letters + string.digits + '-_=')
    
    # Check if all characters are valid Base64 characters
    if all(c in base64_chars for c in text) or all(c in url_safe_chars for c in text):
        # Check for reasonable length
        if len(text) >= 16:  # At least 12 bytes (16 chars)
            # Check padding (if required)
            if check_padding:
                if text.endswith('='):
                    return text.endswith('=') or text.endswith('==')
                return '=' not in text
            return True
    
    return False


def is_printable_text(data: bytes, threshold: float = 0.8) -> bool:
    """
    Check if binary data is likely printable text.
    
    Args:
        data: Binary data to check
        threshold: Minimum ratio of printable characters
        
    Returns:
        True if likely text, False otherwise
    """
    if not data:
        return False
    
    # Count printable characters
    printable_count = sum(32 <= b <= 126 or b in (9, 10, 13) for b in data)
    
    # Calculate ratio
    ratio = printable_count / len(data)
    
    return ratio >= threshold


def is_likely_hex(text: str) -> bool:
    """
    Check if a string is likely hex encoded.
    
    Args:
        text: Text to check
        
    Returns:
        True if likely hex, False otherwise
    """
    # Remove whitespace and common delimiters
    clean_text = re.sub(r'[\s:,]', '', text)
    
    # Remove 0x prefix if present
    if clean_text.lower().startswith('0x'):
        clean_text = clean_text[2:]
    
    # Check if all characters are hex digits
    if all(c in string.hexdigits for c in clean_text):
        # Check length - should be even
        if len(clean_text) % 2 == 0:
            # Check for reasonable length
            if len(clean_text) >= 4:  # At least 2 bytes (4 hex chars)
                return True
    
    return False


def is_likely_ascii85(text: str) -> bool:
    """
    Check if a string is likely ASCII85/Base85 encoded.
    
    Args:
        text: Text to check
        
    Returns:
        True if likely ASCII85, False otherwise
    """
    # Check for Adobe ASCII85 markers
    if text.startswith('<~') and text.endswith('~>'):
        return True
    
    # Check alphabet
    ascii85_chars = set(string.ascii_letters + string.digits + '!#$%&()*+-;<=>?@^_`{|}~')
    
    # Check if all characters are in ASCII85 range and not too many z's
    if all(c in ascii85_chars for c in text):
        # Check for reasonable length
        if len(text) >= 5:  # At least 4 bytes (5 ASCII85 chars)
            # Not too many 'z' (special all-zero group)
            z_count = text.count('z')
            return z_count <= len(text) / 5
    
    return False


def fix_base64_padding(text: str) -> str:
    """
    Fix Base64 padding if needed.
    
    Args:
        text: Base64 text to fix
        
    Returns:
        Fixed Base64 text
    """
    # Remove any whitespace
    text = text.strip()
    
    # Add padding if needed
    padding = len(text) % 4
    if padding:
        text += '=' * (4 - padding)
    
    return text


def is_likely_binary(text: str) -> bool:
    """
    Check if a string is likely binary encoded.
    
    Args:
        text: Text to check
        
    Returns:
        True if likely binary, False otherwise
    """
    # Remove whitespace
    clean_text = re.sub(r'\s', '', text)
    
    # Check if it consists only of 0s and 1s
    if all(bit in '01' for bit in clean_text):
        # Check for reasonable length
        if len(clean_text) >= 8:  # At least 1 byte (8 bits)
            # Prefer multiples of 8, but not required
            return True
    
    # Check for word-like grouping
    words = text.split()
    if len(words) >= 3:
        if all(re.match(r'^[01]+$', word) for word in words):
            if all(8 <= len(word) <= 16 for word in words):
                return True
    
    return False


def apply_rot(text: str, rot: int) -> str:
    """
    Apply ROT encoding.
    
    Args:
        text: Text to encode
        rot: Rotation value (1-25)
        
    Returns:
        ROT encoded text
    """
    result = []
    
    for char in text:
        if char.isalpha():
            ascii_offset = ord('a') if char.islower() else ord('A')
            # Convert to 0-25, add rotation, mod 26, convert back to ASCII
            rotated = chr((ord(char) - ascii_offset + rot) % 26 + ascii_offset)
            result.append(rotated)
        else:
            result.append(char)
    
    return ''.join(result)


def score_english_text(text: str) -> float:
    """
    Score how likely a text is to be English.
    
    Args:
        text: Text to score
        
    Returns:
        Score between 0 and 1
    """
    # Check for common English words
    common_words = {
        'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i',
        'it', 'for', 'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at',
        'this', 'but', 'his', 'by', 'from', 'they', 'we', 'say', 'her', 'she',
        'or', 'an', 'will', 'my', 'one', 'all', 'would', 'there', 'their', 'what',
        'so', 'up', 'out', 'if', 'about', 'who', 'get', 'which', 'go', 'me'
    }
    
    # Split into words
    words = re.findall(r'\b[a-z]+\b', text.lower())
    
    if not words:
        return 0
    
    # Count words that are in the common_words set
    found = sum(1 for word in words if word in common_words)
    
    # Account for text length
    if len(words) < 3:
        return found / len(words) * 0.5  # Penalize very short texts
    
    # Score based on ratio of common words
    return found / len(words) * min(len(words) / 10, 1.0)


def is_likely_bacon_cipher(text: str) -> bool:
    """
    Check if text is likely encoded with Bacon cipher.
    
    Args:
        text: Text to check
        
    Returns:
        True if likely Bacon cipher, False otherwise
    """
    # Remove whitespace
    clean_text = re.sub(r'\s', '', text)
    
    # Check patterns for Bacon cipher (usually A/B or 0/1 in groups of 5)
    pattern1 = re.match(r'^[AB]+$', clean_text) and len(clean_text) % 5 == 0
    pattern2 = re.match(r'^[01]+$', clean_text) and len(clean_text) % 5 == 0
    
    # Check for capital/lowercase pattern
    if not pattern1 and not pattern2:
        # Convert to A/B based on case
        ab_version = ''.join('A' if c.isupper() else 'B' for c in text if c.isalpha())
        pattern3 = len(ab_version) % 5 == 0 and len(ab_version) >= 25  # At least 5 letters
        
        return pattern3
    
    return pattern1 or pattern2


def decode_bacon_cipher(text: str) -> Optional[str]:
    """
    Decode Bacon cipher.
    
    Args:
        text: Encoded text
        
    Returns:
        Decoded text or None if decoding fails
    """
    # Bacon cipher mappings
    bacon_to_letter = {
        'AAAAA': 'A', 'AAAAB': 'B', 'AAABA': 'C', 'AAABB': 'D', 'AABAA': 'E',
        'AABAB': 'F', 'AABBA': 'G', 'AABBB': 'H', 'ABAAA': 'I', 'ABAAB': 'J',
        'ABABA': 'K', 'ABABB': 'L', 'ABBAA': 'M', 'ABBAB': 'N', 'ABBBA': 'O',
        'ABBBB': 'P', 'BAAAA': 'Q', 'BAAAB': 'R', 'BAABA': 'S', 'BAABB': 'T',
        'BABAA': 'U', 'BABAB': 'V', 'BABBA': 'W', 'BABBB': 'X', 'BBAAA': 'Y',
        'BBAAB': 'Z'
    }
    
    # Alternative mappings
    bacon01_to_letter = {k.replace('A', '0').replace('B', '1'): v for k, v in bacon_to_letter.items()}
    
    try:
        # Try standard A/B encoding
        if all(c in 'AB' for c in text if c.isalpha()):
            clean_text = ''.join(c for c in text if c in 'AB')
            if len(clean_text) % 5 != 0:
                return None
            
            result = []
            for i in range(0, len(clean_text), 5):
                group = clean_text[i:i+5]
                if group in bacon_to_letter:
                    result.append(bacon_to_letter[group])
            
            return ''.join(result)
        
        # Try 0/1 encoding
        elif all(c in '01' for c in text if c not in string.whitespace):
            clean_text = ''.join(c for c in text if c in '01')
            if len(clean_text) % 5 != 0:
                return None
            
            result = []
            for i in range(0, len(clean_text), 5):
                group = clean_text[i:i+5]
                if group in bacon01_to_letter:
                    result.append(bacon01_to_letter[group])
            
            return ''.join(result)
        
        # Try case-based encoding
        else:
            case_text = ''.join('A' if c.isupper() else 'B' for c in text if c.isalpha())
            if len(case_text) % 5 != 0:
                return None
            
            result = []
            for i in range(0, len(case_text), 5):
                group = case_text[i:i+5]
                if group in bacon_to_letter:
                    result.append(bacon_to_letter[group])
            
            return ''.join(result)
    
    except Exception as e:
        logger.debug(f"Error decoding Bacon cipher: {e}")
        return None


def is_likely_morse_code(text: str) -> bool:
    """
    Check if text is likely Morse code.
    
    Args:
        text: Text to check
        
    Returns:
        True if likely Morse code, False otherwise
    """
    # Check for standard Morse code characters
    morse_chars = set('.,-/ ')
    
    # Alternative representations
    alt_morse = {
        '·-': '.-',  # Unicode dot
        '—': '-',    # Em dash
        '_': '-',    # Underscore
        '–': '-',    # En dash
        ' ': ' ',    # Space
        '/': '/',    # Slash
    }
    
    # Clean and normalize text
    clean_text = text
    for alt, std in alt_morse.items():
        clean_text = clean_text.replace(alt, std)
    
    # Remove extra whitespace
    clean_text = re.sub(r'\s+', ' ', clean_text).strip()
    
    # Check if text contains mainly Morse characters
    if all(c in morse_chars for c in clean_text):
        # Split into letters
        letters = clean_text.split(' ')
        
        # Check if letters look like Morse code
        morse_pattern = re.compile(r'^[.-]+$')
        valid_letters = sum(1 for letter in letters if morse_pattern.match(letter))
        
        # At least 60% of non-empty segments should match morse pattern
        non_empty = sum(1 for letter in letters if letter)
        if non_empty > 0 and valid_letters / non_empty >= 0.6:
            return True
    
    return False


def decode_morse_code(text: str) -> Optional[str]:
    """
    Decode Morse code.
    
    Args:
        text: Encoded text
        
    Returns:
        Decoded text or None if decoding fails
    """
    morse_to_char = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
        '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
        '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
        '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
        '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
        '--..': 'Z', '.----': '1', '..---': '2', '...--': '3', '....-': '4',
        '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9',
        '-----': '0', '.-.-.-': '.', '--..--': ',', '..--..': '?',
        '.----.': "'", '-.-.--': '!', '-..-.': '/', '-.--.': '(', '-.--.-': ')',
        '.-...': '&', '---...': ':', '-.-.-.': ';', '-...-': '=', '.-.-.': '+',
        '-....-': '-', '..--.-': '_', '.-..-.': '"', '...-..-': '$',
        '.--.-.': '@', '...---...': 'SOS'
    }
    
    # Alternative representations
    alt_morse = {
        '·': '.',    # Unicode dot
        '—': '-',    # Em dash
        '_': '-',    # Underscore
        '–': '-',    # En dash
    }
    
    try:
        # Clean and normalize text
        clean_text = text
        for alt, std in alt_morse.items():
            clean_text = clean_text.replace(alt, std)
        
        # Remove extra whitespace
        clean_text = re.sub(r'\s+', ' ', clean_text).strip()
        
        # Split into words and letters
        words = clean_text.split(' / ')
        if len(words) == 1:
            # Try different word separators
            words = clean_text.split('/ ')
            if len(words) == 1:
                words = clean_text.split(' /')
                if len(words) == 1:
                    words = clean_text.split('/')
        
        result = []
        for word in words:
            letters = word.strip().split(' ')
            word_result = []
            
            for letter in letters:
                if letter in morse_to_char:
                    word_result.append(morse_to_char[letter])
                elif letter:  # Skip empty letters
                    word_result.append('?')  # Unknown Morse code
            
            if word_result:
                result.append(''.join(word_result))
        
        return ' '.join(result)
    
    except Exception as e:
        logger.debug(f"Error decoding Morse code: {e}")
        return None


def is_likely_nato_phonetic(text: str) -> bool:
    """
    Check if text is likely NATO phonetic alphabet.
    
    Args:
        text: Text to check
        
    Returns:
        True if likely NATO phonetic, False otherwise
    """
    # NATO phonetic words
    nato_words = {
        'alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot', 'golf',
        'hotel', 'india', 'juliet', 'kilo', 'lima', 'mike', 'november',
        'oscar', 'papa', 'quebec', 'romeo', 'sierra', 'tango', 'uniform',
        'victor', 'whiskey', 'xray', 'yankee', 'zulu'
    }
    
    # Check for presence of NATO words
    words = re.findall(r'\b[a-z]+\b', text.lower())
    
    if not words:
        return False
    
    # Count NATO words
    nato_count = sum(1 for word in words if word in nato_words)
    
    # At least 40% of words should be NATO phonetic
    return nato_count >= len(words) * 0.4 and nato_count >= 3


def decode_nato_phonetic(text: str) -> Optional[str]:
    """
    Decode NATO phonetic alphabet.
    
    Args:
        text: Encoded text
        
    Returns:
        Decoded text or None if decoding fails
    """
    nato_to_letter = {
        'alpha': 'A', 'bravo': 'B', 'charlie': 'C', 'delta': 'D', 'echo': 'E',
        'foxtrot': 'F', 'golf': 'G', 'hotel': 'H', 'india': 'I', 'juliet': 'J',
        'kilo': 'K', 'lima': 'L', 'mike': 'M', 'november': 'N', 'oscar': 'O',
        'papa': 'P', 'quebec': 'Q', 'romeo': 'R', 'sierra': 'S', 'tango': 'T',
        'uniform': 'U', 'victor': 'V', 'whiskey': 'W', 'xray': 'X', 'yankee': 'Y',
        'zulu': 'Z'
    }
    
    try:
        words = re.findall(r'\b[a-z]+\b', text.lower())
        result = []
        
        for word in words:
            if word in nato_to_letter:
                result.append(nato_to_letter[word])
            else:
                # If it's not a NATO word, keep it as is
                result.append(word)
        
        return ''.join(result)
    
    except Exception as e:
        logger.debug(f"Error decoding NATO phonetic: {e}")
        return None
