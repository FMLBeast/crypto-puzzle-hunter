"""
Text analyzer module for Crypto Hunter

This module provides functions for analyzing and decoding text-based cryptographic puzzles.
"""
import logging
import re
import string
import base64
import binascii
from typing import Dict, List, Any, Optional, Tuple, Union
from collections import Counter

from core.state import State
from analyzers.base import register_analyzer, analyzer_compatibility

logger = logging.getLogger(__name__)


@register_analyzer("text_analyze")
@analyzer_compatibility(requires_text=True)
def analyze_text(state: State) -> State:
    """
    Main text analyzer function that orchestrates text analysis.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_text:
        state.add_insight("No text data available for analysis", analyzer="text_analyzer")
        return state
    
    # Run various text analysis functions
    state = detect_encodings(state)
    state = analyze_character_frequency(state)
    state = identify_cipher_type(state)
    state = extract_patterns(state)
    
    return state


@register_analyzer("detect_encodings")
@analyzer_compatibility(requires_text=True)
def detect_encodings(state: State) -> State:
    """
    Detect common encoding schemes in the text.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_text:
        return state
    
    text = state.puzzle_text.strip()
    
    # Check for Base64 encoding
    if is_base64(text):
        state.add_insight("Text appears to be Base64 encoded", analyzer="text_analyzer")
        try:
            decoded = base64.b64decode(text).decode('utf-8')
            state.add_transformation(
                name="base64_decode",
                description="Decoded Base64 to text",
                input_data=text,
                output_data=decoded,
                analyzer="text_analyzer"
            )
            state.puzzle_text = decoded
        except Exception as e:
            state.add_insight(f"Failed to decode Base64: {e}", analyzer="text_analyzer")
    
    # Check for Hex encoding
    elif is_hex(text):
        state.add_insight("Text appears to be hex encoded", analyzer="text_analyzer")
        try:
            decoded = bytes.fromhex(text).decode('utf-8')
            state.add_transformation(
                name="hex_decode",
                description="Decoded hex to text",
                input_data=text,
                output_data=decoded,
                analyzer="text_analyzer"
            )
            state.puzzle_text = decoded
        except Exception as e:
            state.add_insight(f"Failed to decode hex: {e}", analyzer="text_analyzer")
    
    # Check for ASCII85/Base85 encoding
    elif is_ascii85(text):
        state.add_insight("Text might be ASCII85/Base85 encoded", analyzer="text_analyzer")
        try:
            # Try to decode as ASCII85
            decoded = base64.a85decode(text).decode('utf-8')
            state.add_transformation(
                name="ascii85_decode",
                description="Decoded ASCII85 to text",
                input_data=text,
                output_data=decoded,
                analyzer="text_analyzer"
            )
            state.puzzle_text = decoded
        except Exception as e:
            state.add_insight(f"Failed to decode ASCII85: {e}", analyzer="text_analyzer")
    
    # Check for URL encoding
    elif '%' in text and is_url_encoded(text):
        state.add_insight("Text appears to be URL encoded", analyzer="text_analyzer")
        try:
            import urllib.parse
            decoded = urllib.parse.unquote(text)
            state.add_transformation(
                name="url_decode",
                description="Decoded URL encoding to text",
                input_data=text,
                output_data=decoded,
                analyzer="text_analyzer"
            )
            state.puzzle_text = decoded
        except Exception as e:
            state.add_insight(f"Failed to decode URL encoding: {e}", analyzer="text_analyzer")
    
    # Check for Binary encoding
    elif is_binary(text):
        state.add_insight("Text appears to be binary encoded", analyzer="text_analyzer")
        try:
            # Convert binary to ASCII
            binary_values = text.split()
            decoded = ''.join([chr(int(binary, 2)) for binary in binary_values])
            state.add_transformation(
                name="binary_decode",
                description="Decoded binary to text",
                input_data=text,
                output_data=decoded,
                analyzer="text_analyzer"
            )
            state.puzzle_text = decoded
        except Exception as e:
            state.add_insight(f"Failed to decode binary: {e}", analyzer="text_analyzer")
    
    # Check for ROT13 encoding
    rot13_decoded = apply_rot13(text)
    if is_english_like(rot13_decoded) and not is_english_like(text):
        state.add_insight("Text appears to be ROT13 encoded", analyzer="text_analyzer")
        state.add_transformation(
            name="rot13_decode",
            description="Decoded ROT13 to text",
            input_data=text,
            output_data=rot13_decoded,
            analyzer="text_analyzer"
        )
        state.puzzle_text = rot13_decoded
    
    return state


@register_analyzer("analyze_character_frequency")
@analyzer_compatibility(requires_text=True)
def analyze_character_frequency(state: State) -> State:
    """
    Analyze character frequency in the text for cryptanalysis.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_text:
        return state
    
    text = state.puzzle_text.strip()
    
    # Skip if text is too short
    if len(text) < 20:
        return state
    
    # Compute character frequency
    chars = [c for c in text if c.isalpha()]
    freq = Counter(chars)
    total = len(chars)
    
    if not total:
        return state
    
    # Compute frequency percentages
    freq_percent = {char: (count / total) * 100 for char, count in freq.items()}
    
    # Get the most common characters
    most_common = freq.most_common(5)
    
    # English letter frequency (approximate)
    english_freq = {
        'e': 12.02, 't': 9.10, 'a': 8.12, 'o': 7.68, 'i': 7.31,
        'n': 6.95, 's': 6.28, 'r': 6.02, 'h': 5.92, 'd': 4.32,
        'l': 3.98, 'u': 2.88, 'c': 2.71, 'm': 2.61, 'f': 2.30,
        'y': 2.11, 'w': 2.09, 'g': 2.03, 'p': 1.82, 'b': 1.49,
        'v': 1.11, 'k': 0.69, 'x': 0.17, 'q': 0.11, 'j': 0.10, 'z': 0.07
    }
    
    # Add insights about frequency analysis
    state.add_insight(
        f"Character frequency analysis: most common letters are {', '.join([f'{c[0]} ({c[1]})' for c in most_common])}",
        analyzer="text_analyzer",
        data={"frequency": {k: v for k, v in freq_percent.items()}}
    )
    
    # Check if this might be a substitution cipher
    if set(freq_percent.keys()).issubset(set(string.ascii_letters)):
        state.add_insight(
            "Character frequency suggests this might be a substitution cipher",
            analyzer="text_analyzer"
        )
        
        # Try to match with English letter frequency for simple substitution
        if len(freq_percent) >= 20 and all(c.islower() for c in freq_percent.keys()):
            mapping = {}
            for char, _ in sorted(freq_percent.items(), key=lambda x: x[1], reverse=True):
                english_char = sorted(english_freq.items(), key=lambda x: x[1], reverse=True)[len(mapping)][0]
                mapping[char] = english_char
                if len(mapping) >= len(english_freq):
                    break
            
            # Apply the mapping
            decoded = ''.join(mapping.get(c, c) for c in text)
            state.add_transformation(
                name="frequency_substitution",
                description="Applied frequency-based substitution",
                input_data=text,
                output_data=decoded,
                analyzer="text_analyzer"
            )
    
    return state


@register_analyzer("identify_cipher_type")
@analyzer_compatibility(requires_text=True)
def identify_cipher_type(state: State) -> State:
    """
    Attempt to identify the type of cipher used in the text.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_text:
        return state
    
    text = state.puzzle_text.strip()
    
    # Apply common cipher detection techniques
    
    # Check for Caesar cipher
    likely_shift = detect_caesar_shift(text)
    if likely_shift > 0:
        state.add_insight(
            f"Text appears to be a Caesar cipher with shift {likely_shift}",
            analyzer="text_analyzer"
        )
        decoded = apply_caesar_shift(text, likely_shift)
        state.add_transformation(
            name="caesar_decode",
            description=f"Decoded Caesar cipher with shift {likely_shift}",
            input_data=text,
            output_data=decoded,
            analyzer="text_analyzer"
        )
        state.puzzle_text = decoded
    
    # Check for Atbash cipher
    if is_likely_atbash(text):
        state.add_insight("Text may be encoded with Atbash cipher", analyzer="text_analyzer")
        decoded = apply_atbash(text)
        state.add_transformation(
            name="atbash_decode",
            description="Decoded Atbash cipher",
            input_data=text,
            output_data=decoded,
            analyzer="text_analyzer"
        )
        state.puzzle_text = decoded
    
    # Check for Vigenère cipher markers
    if has_vigenere_characteristics(text):
        state.add_insight(
            "Text has characteristics of a Vigenère cipher",
            analyzer="text_analyzer"
        )
        # Attempt to determine the key length
        possible_key_lengths = find_vigenere_key_length(text)
        if possible_key_lengths:
            state.add_insight(
                f"Possible Vigenère key lengths: {', '.join(map(str, possible_key_lengths[:3]))}",
                analyzer="text_analyzer",
                data={"key_lengths": possible_key_lengths}
            )
    
    return state


@register_analyzer("extract_patterns")
@analyzer_compatibility(requires_text=True)
def extract_patterns(state: State) -> State:
    """
    Extract patterns and potential clues from the text.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_text:
        return state
    
    text = state.puzzle_text.strip()
    
    # Look for common cryptographic puzzle patterns
    
    # Check for CTF flag formats
    flag_patterns = [
        r"flag{[^}]*}",
        r"FLAG{[^}]*}",
        r"ctf{[^}]*}",
        r"CTF{[^}]*}",
    ]
    
    for pattern in flag_patterns:
        matches = re.findall(pattern, text)
        if matches:
            state.add_insight(
                f"Found potential flag: {matches[0]}",
                analyzer="text_analyzer",
                data={"flags": matches}
            )
    
    # Look for potential keywords
    crypto_keywords = [
        "secret", "password", "key", "decrypt", "encrypt", "cipher",
        "hash", "hidden", "code", "puzzle", "solve", "crypto"
    ]
    
    for keyword in crypto_keywords:
        if keyword.lower() in text.lower():
            # Find the context around the keyword
            index = text.lower().find(keyword.lower())
            start = max(0, index - 20)
            end = min(len(text), index + len(keyword) + 20)
            context = text[start:end]
            
            state.add_insight(
                f"Found crypto keyword '{keyword}' in context: '{context}'",
                analyzer="text_analyzer"
            )
    
    # Check for patterns of numbers that might be ASCII codes
    ascii_pattern = r"\b(?:1[01]\d|12[0-7]|[1-9]\d|[1-9])\b"
    number_matches = re.findall(ascii_pattern, text)
    
    if len(number_matches) > 3:
        try:
            # Try to convert numbers to ASCII
            ascii_text = ''.join([chr(int(num)) for num in number_matches])
            if is_english_like(ascii_text):
                state.add_insight(
                    f"Numbers might represent ASCII codes: '{ascii_text}'",
                    analyzer="text_analyzer"
                )
                state.add_transformation(
                    name="ascii_code_decode",
                    description="Converted numbers to ASCII characters",
                    input_data=' '.join(number_matches),
                    output_data=ascii_text,
                    analyzer="text_analyzer"
                )
        except:
            pass
    
    # Look for encoded URLs
    url_pattern = r"https?://[^\s]+"
    urls = re.findall(url_pattern, text)
    
    if urls:
        state.add_insight(
            f"Found URLs in the text: {', '.join(urls[:3])}",
            analyzer="text_analyzer",
            data={"urls": urls}
        )
    
    return state


# Helper functions

def is_base64(text: str) -> bool:
    """Check if a string is Base64 encoded."""
    # Base64 uses only alphanumeric characters, +, /, and = for padding
    if not re.match(r'^[A-Za-z0-9+/]+={0,2}$', text.strip()):
        return False
    
    # Base64 length must be a multiple of 4
    if len(text.strip()) % 4 != 0:
        return False
    
    # Try to decode it
    try:
        base64.b64decode(text)
        return True
    except Exception:
        return False


def is_hex(text: str) -> bool:
    """Check if a string is hex encoded."""
    # Hex strings contain only hex characters
    if not re.match(r'^[A-Fa-f0-9]+$', text.strip()):
        return False
    
    # Hex strings should have an even length
    if len(text.strip()) % 2 != 0:
        return False
    
    # Try to decode it
    try:
        bytes.fromhex(text.strip())
        return True
    except Exception:
        return False


def is_ascii85(text: str) -> bool:
    """Check if a string is likely ASCII85/Base85 encoded."""
    # ASCII85 uses a limited character set
    if not re.match(r'^[!-uz]+~?>$', text.strip()):
        return False
    
    # Try to decode it
    try:
        base64.a85decode(text)
        return True
    except Exception:
        return False


def is_url_encoded(text: str) -> bool:
    """Check if a string is URL encoded."""
    # URL encoded strings often contain % followed by two hex digits
    if not re.search(r'%[0-9A-Fa-f]{2}', text):
        return False
    
    # Try to decode it
    try:
        import urllib.parse
        decoded = urllib.parse.unquote(text)
        # If decoded is different, it was URL encoded
        return decoded != text
    except Exception:
        return False


def is_binary(text: str) -> bool:
    """Check if a string is binary encoded."""
    # Binary strings contain only 0s and 1s, possibly with spaces
    return bool(re.match(r'^[01\s]+$', text.strip()))


def apply_rot13(text: str) -> str:
    """Apply ROT13 transformation to a string."""
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord('a') if char.islower() else ord('A')
            rotated = (ord(char) - ascii_offset + 13) % 26 + ascii_offset
            result += chr(rotated)
        else:
            result += char
    return result


def is_english_like(text: str) -> bool:
    """Check if a string appears to be English text."""
    # Calculate the percentage of common English letters
    common_letters = 'etaoinshrdlucmfwypvbgkjqxz'
    letter_count = sum(1 for c in text.lower() if c in common_letters)
    total_letters = sum(1 for c in text if c.isalpha())
    
    if total_letters == 0:
        return False
    
    # Check if there is a high ratio of common English letters
    common_ratio = letter_count / total_letters
    if common_ratio < 0.7:
        return False
    
    # Check for common English words
    common_words = [
        'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i',
        'it', 'for', 'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at'
    ]
    
    word_count = sum(1 for word in text.lower().split() if word in common_words)
    total_words = len(text.split())
    
    if total_words == 0:
        return False
    
    # Check if there is a reasonable ratio of common English words
    word_ratio = word_count / total_words
    
    return word_ratio > 0.1


def detect_caesar_shift(text: str) -> int:
    """Detect the most likely Caesar cipher shift."""
    # Only consider alphabetic characters
    alpha_text = ''.join(c.lower() for c in text if c.isalpha())
    
    if not alpha_text:
        return 0
    
    # Score each possible shift based on letter frequency
    english_freq = {
        'e': 12.02, 't': 9.10, 'a': 8.12, 'o': 7.68, 'i': 7.31,
        'n': 6.95, 's': 6.28, 'r': 6.02, 'h': 5.92, 'd': 4.32,
        'l': 3.98, 'u': 2.88, 'c': 2.71, 'm': 2.61, 'f': 2.30,
        'y': 2.11, 'w': 2.09, 'g': 2.03, 'p': 1.82, 'b': 1.49,
        'v': 1.11, 'k': 0.69, 'x': 0.17, 'q': 0.11, 'j': 0.10, 'z': 0.07
    }
    
    best_score = 0
    best_shift = 0
    
    for shift in range(1, 26):
        score = 0
        shifted_text = apply_caesar_shift(alpha_text, shift)
        freq = Counter(shifted_text)
        total = len(shifted_text)
        
        # Calculate score based on English letter frequency
        for char, count in freq.items():
            if char in english_freq:
                expected = english_freq[char] * total / 100
                score += min(count, expected) / max(count, expected)
        
        if score > best_score:
            best_score = score
            best_shift = shift
    
    # Only return if the score is significant
    return best_shift if best_score > 10 else 0


def apply_caesar_shift(text: str, shift: int) -> str:
    """Apply a Caesar cipher shift to a string."""
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord('a') if char.islower() else ord('A')
            shifted = (ord(char) - ascii_offset + shift) % 26 + ascii_offset
            result += chr(shifted)
        else:
            result += char
    return result


def is_likely_atbash(text: str) -> bool:
    """Check if a string is likely encoded with Atbash cipher."""
    # Atbash should have a similar frequency distribution as the original text
    # but with different characters
    alpha_text = ''.join(c.lower() for c in text if c.isalpha())
    
    if not alpha_text:
        return False
    
    # Check if applying Atbash produces more English-like text
    atbash_text = apply_atbash(alpha_text)
    
    return is_english_like(atbash_text) and not is_english_like(alpha_text)


def apply_atbash(text: str) -> str:
    """Apply Atbash cipher transformation to a string."""
    result = ""
    for char in text:
        if char.islower():
            result += chr(219 - ord(char))  # 219 = ord('a') + ord('z')
        elif char.isupper():
            result += chr(155 - ord(char))  # 155 = ord('A') + ord('Z')
        else:
            result += char
    return result


def has_vigenere_characteristics(text: str) -> bool:
    """Check if a string has characteristics of a Vigenère cipher."""
    # Vigenère typically has more evenly distributed character frequencies
    # than simple substitution ciphers
    alpha_text = ''.join(c.lower() for c in text if c.isalpha())
    
    if len(alpha_text) < 30:
        return False
    
    freq = Counter(alpha_text)
    values = list(freq.values())
    
    if not values:
        return False
    
    # Calculate standard deviation of frequencies
    mean = sum(values) / len(values)
    variance = sum((x - mean) ** 2 for x in values) / len(values)
    std_dev = variance ** 0.5
    
    # Vigenère tends to have a lower standard deviation
    return std_dev < mean / 2


def find_vigenere_key_length(text: str) -> List[int]:
    """
    Find possible key lengths for a Vigenère cipher using the Index of Coincidence.
    
    Returns a list of potential key lengths sorted by likelihood.
    """
    alpha_text = ''.join(c.lower() for c in text if c.isalpha())
    
    if len(alpha_text) < 30:
        return []
    
    # Calculate Index of Coincidence for different key lengths
    ic_scores = []
    for key_length in range(2, 21):  # Try key lengths 2-20
        if len(alpha_text) < key_length * 2:
            continue
        
        # Split text into groups based on key length
        groups = [''] * key_length
        for i, char in enumerate(alpha_text):
            groups[i % key_length] += char
        
        # Calculate average IC for all groups
        avg_ic = 0
        for group in groups:
            freq = Counter(group)
            n = len(group)
            if n <= 1:
                continue
                
            # Calculate Index of Coincidence
            ic = sum(count * (count - 1) for count in freq.values()) / (n * (n - 1))
            avg_ic += ic
        
        avg_ic /= key_length
        ic_scores.append((key_length, avg_ic))
    
    # English has an IC of ~0.067, so higher scores are more likely English
    # Sort by IC score, descending
    ic_scores.sort(key=lambda x: x[1], reverse=True)
    
    # Return the key lengths sorted by likelihood
    return [length for length, _ in ic_scores if _ > 0.05]
