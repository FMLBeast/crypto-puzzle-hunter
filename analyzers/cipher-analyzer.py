"""
Cipher analyzer module for Crypto Hunter

This module provides functions for detecting and solving
various cryptographic ciphers like Caesar, Vigenère, substitution, etc.
"""
import logging
import re
import string
import math
from typing import Dict, List, Any, Optional, Tuple, Union
from collections import Counter

from core.state import State
from analyzers.base import register_analyzer, analyzer_compatibility

logger = logging.getLogger(__name__)


@register_analyzer("cipher_analyze")
@analyzer_compatibility(requires_text=True)
def analyze_cipher(state: State) -> State:
    """
    Main cipher analyzer function that detects and solves various ciphers.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_text:
        state.add_insight("No text data available for cipher analysis", analyzer="cipher_analyzer")
        return state
    
    # Run various cipher analysis functions
    state = detect_and_solve_caesar(state)
    state = detect_and_solve_substitution(state)
    state = detect_and_solve_vigenere(state)
    state = detect_and_solve_transposition(state)
    state = detect_and_solve_xor(state)
    state = detect_and_solve_atbash(state)
    state = detect_and_solve_railfence(state)
    
    return state


@register_analyzer("detect_and_solve_caesar")
@analyzer_compatibility(requires_text=True)
def detect_and_solve_caesar(state: State) -> State:
    """
    Detect and solve Caesar cipher.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_text:
        return state
    
    text = state.puzzle_text.strip()
    
    # Skip if text is too short or has too many non-alphabetic characters
    if len(text) < 10:
        return state
    
    # Count alphabetic characters
    alpha_count = sum(c.isalpha() for c in text)
    if alpha_count / len(text) < 0.7:
        return state
    
    # Try to detect the shift using frequency analysis
    shift = detect_caesar_shift(text)
    
    if shift > 0:
        # Apply the shift
        deciphered = apply_caesar_shift(text, shift)
        
        # Check if the result seems like readable text
        if score_english_text(deciphered) > 0.6:
            state.add_insight(
                f"Text appears to be a Caesar cipher with shift {shift}",
                analyzer="cipher_analyzer",
                confidence=0.8
            )
            state.add_transformation(
                name="caesar_decipher",
                description=f"Deciphered Caesar cipher with shift {shift}",
                input_data=text,
                output_data=deciphered,
                analyzer="cipher_analyzer"
            )
            
            # Update puzzle text with deciphered text
            state.puzzle_text = deciphered
    
    return state


@register_analyzer("detect_and_solve_substitution")
@analyzer_compatibility(requires_text=True)
def detect_and_solve_substitution(state: State) -> State:
    """
    Detect and solve simple substitution cipher.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_text:
        return state
    
    text = state.puzzle_text.strip()
    
    # Skip if text is too short or has too many non-alphabetic characters
    if len(text) < 50:  # Need more text for frequency analysis
        return state
    
    # Count alphabetic characters
    alpha_text = ''.join(c for c in text if c.isalpha()).lower()
    if len(alpha_text) < 50:
        return state
    
    # Check if frequency analysis suggests a substitution cipher
    if is_likely_substitution_cipher(alpha_text):
        # Try to solve using frequency analysis
        mapping = solve_substitution_cipher(alpha_text)
        
        if mapping:
            # Apply the mapping
            deciphered = apply_substitution_mapping(text, mapping)
            
            # Check if the result seems like readable text
            if score_english_text(deciphered) > 0.5:
                state.add_insight(
                    "Text appears to be a simple substitution cipher",
                    analyzer="cipher_analyzer",
                    confidence=0.7,
                    data={"mapping": mapping}
                )
                state.add_transformation(
                    name="substitution_decipher",
                    description="Deciphered substitution cipher using frequency analysis",
                    input_data=text,
                    output_data=deciphered,
                    analyzer="cipher_analyzer"
                )
                
                # Update puzzle text with deciphered text
                state.puzzle_text = deciphered
    
    return state


@register_analyzer("detect_and_solve_vigenere")
@analyzer_compatibility(requires_text=True)
def detect_and_solve_vigenere(state: State) -> State:
    """
    Detect and solve Vigenère cipher.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_text:
        return state
    
    text = state.puzzle_text.strip()
    
    # Skip if text is too short
    if len(text) < 50:
        return state
    
    # Count alphabetic characters
    alpha_text = ''.join(c for c in text if c.isalpha())
    if len(alpha_text) < 50:
        return state
    
    # Check if it may be a Vigenère cipher
    if is_likely_vigenere_cipher(alpha_text):
        # Try to find the key length
        key_length = find_vigenere_key_length(alpha_text)
        
        if key_length > 0:
            # Try to find the key
            key = find_vigenere_key(alpha_text, key_length)
            
            if key:
                # Apply the key
                deciphered = decrypt_vigenere(alpha_text, key)
                
                # Check if the result seems like readable text
                if score_english_text(deciphered) > 0.5:
                    state.add_insight(
                        f"Text appears to be a Vigenère cipher with key '{key}'",
                        analyzer="cipher_analyzer",
                        confidence=0.7,
                        data={"key": key, "key_length": key_length}
                    )
                    
                    # Now decipher the original text (preserving non-alpha chars)
                    full_deciphered = decrypt_vigenere_preserve_format(text, key)
                    
                    state.add_transformation(
                        name="vigenere_decipher",
                        description=f"Deciphered Vigenère cipher with key '{key}'",
                        input_data=text,
                        output_data=full_deciphered,
                        analyzer="cipher_analyzer"
                    )
                    
                    # Update puzzle text with deciphered text
                    state.puzzle_text = full_deciphered
    
    return state


@register_analyzer("detect_and_solve_transposition")
@analyzer_compatibility(requires_text=True)
def detect_and_solve_transposition(state: State) -> State:
    """
    Detect and solve transposition ciphers.

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
    
    # Remove spaces for columnar transposition
    clean_text = ''.join(c for c in text if not c.isspace())
    
    # Try different key lengths for columnar transposition
    best_score = 0
    best_key_length = 0
    best_deciphered = ""
    
    # Try key lengths from 2 to sqrt(text_length)
    max_key_length = min(20, int(math.sqrt(len(clean_text))))
    
    for key_length in range(2, max_key_length + 1):
        deciphered = decrypt_columnar(clean_text, key_length)
        score = score_english_text(deciphered)
        
        if score > best_score:
            best_score = score
            best_key_length = key_length
            best_deciphered = deciphered
    
    # If we found a good key length
    if best_score > 0.5:
        state.add_insight(
            f"Text appears to be a columnar transposition cipher with {best_key_length} columns",
            analyzer="cipher_analyzer",
            confidence=best_score,
            data={"key_length": best_key_length}
        )
        state.add_transformation(
            name="columnar_transposition_decipher",
            description=f"Deciphered columnar transposition with {best_key_length} columns",
            input_data=text,
            output_data=best_deciphered,
            analyzer="cipher_analyzer"
        )
        
        # Update puzzle text with deciphered text
        state.puzzle_text = best_deciphered
    else:
        # Try reversed text (simple transposition)
        reversed_text = text[::-1]
        score = score_english_text(reversed_text)
        
        if score > 0.5:
            state.add_insight(
                "Text appears to be reversed",
                analyzer="cipher_analyzer",
                confidence=score
            )
            state.add_transformation(
                name="reverse_text",
                description="Reversed the text",
                input_data=text,
                output_data=reversed_text,
                analyzer="cipher_analyzer"
            )
            
            # Update puzzle text with reversed text
            state.puzzle_text = reversed_text
        else:
            # Try reading backwards by word
            words = text.split()
            reversed_words = ' '.join(words[::-1])
            score = score_english_text(reversed_words)
            
            if score > 0.5:
                state.add_insight(
                    "Text appears to have words in reverse order",
                    analyzer="cipher_analyzer",
                    confidence=score
                )
                state.add_transformation(
                    name="reverse_words",
                    description="Reversed the word order",
                    input_data=text,
                    output_data=reversed_words,
                    analyzer="cipher_analyzer"
                )
                
                # Update puzzle text with reversed words
                state.puzzle_text = reversed_words
    
    return state


@register_analyzer("detect_and_solve_xor")
@analyzer_compatibility(requires_text=True)
def detect_and_solve_xor(state: State) -> State:
    """
    Detect and solve XOR cipher.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_text:
        return state
    
    # If the text is already binary data, analyze it
    if state.puzzle_data:
        data = state.puzzle_data
        
        # Try single-byte XOR keys
        best_score = 0
        best_key = 0
        best_decrypted = b""
        
        for key in range(1, 256):
            decrypted = bytes(b ^ key for b in data)
            
            # Check if the decrypted data might be text
            if is_printable_text(decrypted):
                try:
                    decoded_text = decrypted.decode('utf-8', errors='replace')
                    score = score_english_text(decoded_text)
                    
                    if score > best_score:
                        best_score = score
                        best_key = key
                        best_decrypted = decrypted
                except:
                    pass
        
        # If we found a good key
        if best_score > 0.5:
            decoded_text = best_decrypted.decode('utf-8', errors='replace')
            state.add_insight(
                f"Binary data appears to be XOR encrypted with key 0x{best_key:02x}",
                analyzer="cipher_analyzer",
                confidence=best_score,
                data={"key": best_key}
            )
            state.add_transformation(
                name="single_byte_xor_decrypt",
                description=f"Decrypted XOR with key 0x{best_key:02x}",
                input_data=data,
                output_data=decoded_text,
                analyzer="cipher_analyzer"
            )
            
            # Update puzzle text with decrypted text
            state.puzzle_text = decoded_text
        else:
            # Try repeating-key XOR with short keys
            for key_length in range(2, 5):  # Try keys of length 2-4
                key = find_repeating_key_xor(data, key_length)
                
                if key:
                    decrypted = decrypt_repeating_key_xor(data, key)
                    
                    # Check if the decrypted data might be text
                    if is_printable_text(decrypted):
                        try:
                            decoded_text = decrypted.decode('utf-8', errors='replace')
                            score = score_english_text(decoded_text)
                            
                            if score > 0.5:
                                key_hex = ''.join(f'{b:02x}' for b in key)
                                state.add_insight(
                                    f"Binary data appears to be XOR encrypted with repeating key '{key_hex}'",
                                    analyzer="cipher_analyzer",
                                    confidence=score,
                                    data={"key": key_hex}
                                )
                                state.add_transformation(
                                    name="repeating_key_xor_decrypt",
                                    description=f"Decrypted XOR with key '{key_hex}'",
                                    input_data=data,
                                    output_data=decoded_text,
                                    analyzer="cipher_analyzer"
                                )
                                
                                # Update puzzle text with decrypted text
                                state.puzzle_text = decoded_text
                                break
                        except:
                            pass
    
    # Try to convert text to byte array and analyze
    else:
        text = state.puzzle_text.strip()
        
        # Skip if text is too short
        if len(text) < 10:
            return state
        
        # Check if it looks like hex data
        if all(c in string.hexdigits for c in text) and len(text) % 2 == 0:
            try:
                data = bytes.fromhex(text)
                
                # Recursive call with binary data
                state.puzzle_data = data
                return detect_and_solve_xor(state)
            except:
                pass
    
    return state


@register_analyzer("detect_and_solve_atbash")
@analyzer_compatibility(requires_text=True)
def detect_and_solve_atbash(state: State) -> State:
    """
    Detect and solve Atbash cipher.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_text:
        return state
    
    text = state.puzzle_text.strip()
    
    # Skip if text is too short
    if len(text) < 10:
        return state
    
    # Count alphabetic characters
    alpha_count = sum(c.isalpha() for c in text)
    if alpha_count / len(text) < 0.7:
        return state
    
    # Apply Atbash transformation
    deciphered = apply_atbash(text)
    
    # Check if the result seems like readable text
    score = score_english_text(deciphered)
    
    if score > 0.5:
        state.add_insight(
            "Text appears to be an Atbash cipher",
            analyzer="cipher_analyzer",
            confidence=score
        )
        state.add_transformation(
            name="atbash_decipher",
            description="Deciphered Atbash cipher",
            input_data=text,
            output_data=deciphered,
            analyzer="cipher_analyzer"
        )
        
        # Update puzzle text with deciphered text
        state.puzzle_text = deciphered
    
    return state


@register_analyzer("detect_and_solve_railfence")
@analyzer_compatibility(requires_text=True)
def detect_and_solve_railfence(state: State) -> State:
    """
    Detect and solve Rail Fence (Zig-zag) cipher.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_text:
        return state
    
    text = state.puzzle_text.strip()
    
    # Skip if text is too short
    if len(text) < 15:
        return state
    
    # Remove non-alphabetic characters
    clean_text = ''.join(c for c in text if c.isalpha())
    
    # Try different rail counts
    best_score = 0
    best_rails = 0
    best_deciphered = ""
    
    for rails in range(2, 11):  # Try 2-10 rails
        deciphered = decrypt_railfence(clean_text, rails)
        score = score_english_text(deciphered)
        
        if score > best_score:
            best_score = score
            best_rails = rails
            best_deciphered = deciphered
    
    # If we found a good rail count
    if best_score > 0.5:
        state.add_insight(
            f"Text appears to be a Rail Fence cipher with {best_rails} rails",
            analyzer="cipher_analyzer",
            confidence=best_score,
            data={"rails": best_rails}
        )
        state.add_transformation(
            name="railfence_decipher",
            description=f"Deciphered Rail Fence cipher with {best_rails} rails",
            input_data=text,
            output_data=best_deciphered,
            analyzer="cipher_analyzer"
        )
        
        # Update puzzle text with deciphered text
        state.puzzle_text = best_deciphered
    
    return state


# Helper functions

def detect_caesar_shift(text: str) -> int:
    """
    Detect the shift used in a Caesar cipher using frequency analysis.
    
    Args:
        text: Ciphertext
        
    Returns:
        Detected shift (0 if detection fails)
    """
    # English letter frequency (from most to least common)
    english_frequent_letters = 'etaoinsrhdlucmfywgpbvkjxqz'
    
    # Count the frequency of each letter in the text
    freq = Counter(c.lower() for c in text if c.isalpha())
    
    # Skip if we don't have enough letters
    if len(freq) < 5:
        return 0
    
    # Get the most common letter in the text
    most_common = freq.most_common(1)[0][0]
    
    # Assume 'e' is the most common letter in English
    for expected in 'etaoin':
        # Calculate the shift to transform most_common to expected
        shift = (ord(most_common) - ord(expected)) % 26
        
        # Apply the shift and check if it makes sense
        deciphered = apply_caesar_shift(text, shift)
        
        if score_english_text(deciphered) > 0.5:
            return shift
    
    # If no good match, try all shifts and pick the best one
    best_score = 0
    best_shift = 0
    
    for shift in range(1, 26):
        deciphered = apply_caesar_shift(text, shift)
        score = score_english_text(deciphered)
        
        if score > best_score:
            best_score = score
            best_shift = shift
    
    return best_shift if best_score > 0.5 else 0


def apply_caesar_shift(text: str, shift: int) -> str:
    """
    Apply a Caesar shift to the text.
    
    Args:
        text: Input text
        shift: Shift value (1-25)
        
    Returns:
        Shifted text
    """
    result = []
    
    for char in text:
        if char.isalpha():
            ascii_offset = ord('a') if char.islower() else ord('A')
            shifted = chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            result.append(shifted)
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
        'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'it',
        'for', 'not', 'on', 'with', 'as', 'you', 'do', 'at', 'this', 'but',
        'his', 'by', 'from', 'they', 'we', 'say', 'her', 'she', 'or', 'an',
        'will', 'my', 'one', 'all', 'would', 'there', 'their', 'what', 'so',
        'up', 'out', 'if', 'about', 'who', 'get', 'which', 'go', 'me', 'when'
    }
    
    # Split into words and normalize
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


def is_likely_substitution_cipher(text: str) -> bool:
    """
    Check if a text is likely a simple substitution cipher.
    
    Args:
        text: Text to check
        
    Returns:
        True if likely a substitution cipher, False otherwise
    """
    # Get frequency distribution
    freq = Counter(text.lower())
    
    # Skip if we don't have enough letters
    if len(freq) < 10:
        return False
    
    # Check if the distribution looks like natural language
    # (few very common letters, many uncommon letters)
    values = sorted(freq.values(), reverse=True)
    
    # Check if the top few letters are significantly more common
    if len(values) >= 5:
        ratio = sum(values[:5]) / sum(values)
        return 0.3 <= ratio <= 0.7
    
    return False


def solve_substitution_cipher(text: str) -> Dict[str, str]:
    """
    Attempt to solve a simple substitution cipher using frequency analysis.
    
    Args:
        text: Ciphertext
        
    Returns:
        Mapping from ciphertext to plaintext letters
    """
    # English letter frequency (from most to least common)
    english_freq_order = 'etaoinsrhdlucmfywgpbvkjxqz'
    
    # Count the frequency of each letter in the text
    freq = Counter(text.lower())
    
    # Skip if we don't have enough letters
    if len(freq) < 10:
        return {}
    
    # Create a mapping based on frequency
    cipher_freq_order = ''.join(letter for letter, _ in freq.most_common() if letter.isalpha())
    
    # Create the initial mapping
    mapping = {}
    for i, cipher_char in enumerate(cipher_freq_order):
        if i < len(english_freq_order):
            mapping[cipher_char] = english_freq_order[i]
    
    # Fill in any missing letters
    for cipher_char in string.ascii_lowercase:
        if cipher_char not in mapping:
            for plain_char in string.ascii_lowercase:
                if plain_char not in mapping.values():
                    mapping[cipher_char] = plain_char
                    break
    
    return mapping


def apply_substitution_mapping(text: str, mapping: Dict[str, str]) -> str:
    """
    Apply a substitution mapping to text.
    
    Args:
        text: Input text
        mapping: Mapping from ciphertext to plaintext letters
        
    Returns:
        Deciphered text
    """
    result = []
    
    for char in text:
        if char.lower() in mapping:
            mapped = mapping[char.lower()]
            # Preserve case
            if char.isupper():
                result.append(mapped.upper())
            else:
                result.append(mapped)
        else:
            result.append(char)
    
    return ''.join(result)


def is_likely_vigenere_cipher(text: str) -> bool:
    """
    Check if a text is likely a Vigenère cipher.
    
    Args:
        text: Text to check
        
    Returns:
        True if likely a Vigenère cipher, False otherwise
    """
    # Get frequency analysis for each position
    counters = {}
    for i, char in enumerate(text.lower()):
        if char.isalpha():
            pos = i % 10  # Use modulo 10 as a sample
            if pos not in counters:
                counters[pos] = Counter()
            counters[pos][char] += 1
    
    # Check if different positions have different frequency distributions
    if len(counters) < 3:
        return False
    
    # Compute similarity between distributions
    similarities = []
    positions = sorted(counters.keys())
    
    for i in range(len(positions) - 1):
        for j in range(i + 1, len(positions)):
            pos1, pos2 = positions[i], positions[j]
            counter1, counter2 = counters[pos1], counters[pos2]
            
            # Compare top 5 letters
            top1 = set(letter for letter, _ in counter1.most_common(5))
            top2 = set(letter for letter, _ in counter2.most_common(5))
            
            similarity = len(top1.intersection(top2)) / 5
            similarities.append(similarity)
    
    # If positions have different distributions, it might be Vigenère
    avg_similarity = sum(similarities) / len(similarities) if similarities else 1.0
    return avg_similarity < 0.6


def find_vigenere_key_length(text: str) -> int:
    """
    Find the key length of a Vigenère cipher using index of coincidence.
    
    Args:
        text: Ciphertext
        
    Returns:
        Most likely key length (0 if detection fails)
    """
    # Count only alphabetic characters
    alpha_text = ''.join(c.lower() for c in text if c.isalpha())
    
    # Skip if we don't have enough letters
    if len(alpha_text) < 20:
        return 0
    
    # Try key lengths from 2 to 10
    best_score = 0
    best_length = 0
    
    for key_length in range(2, 11):
        # Split text into columns based on key length
        columns = [''] * key_length
        for i, char in enumerate(alpha_text):
            columns[i % key_length] += char
        
        # Calculate average index of coincidence for each column
        ic_sum = 0
        for column in columns:
            if len(column) < 2:
                continue
                
            # Count letter frequencies
            freq = Counter(column)
            
            # Calculate index of coincidence
            n = len(column)
            sum_freq_squared = sum(count * (count - 1) for count in freq.values())
            ic = sum_freq_squared / (n * (n - 1))
            
            ic_sum += ic
        
        avg_ic = ic_sum / key_length if key_length else 0
        
        # English has an IC of around 0.067, so higher is better
        if avg_ic > best_score:
            best_score = avg_ic
            best_length = key_length
    
    # Require a minimum score (closer to English IC of 0.067)
    return best_length if best_score > 0.05 else 0


def find_vigenere_key(text: str, key_length: int) -> str:
    """
    Find the key of a Vigenère cipher given the key length.
    
    Args:
        text: Ciphertext
        key_length: Length of the key
        
    Returns:
        Most likely key
    """
    # Count only alphabetic characters
    alpha_text = ''.join(c.lower() for c in text if c.isalpha())
    
    # Skip if we don't have enough letters
    if len(alpha_text) < key_length * 2:
        return ""
    
    # Split text into columns based on key length
    columns = [''] * key_length
    for i, char in enumerate(alpha_text):
        columns[i % key_length] += char
    
    # For each column, find the most likely Caesar shift
    key = []
    for column in columns:
        shift = detect_caesar_shift(column)
        
        # Convert shift to letter (0 -> 'a', 1 -> 'b', etc.)
        key_char = chr((26 - shift) % 26 + ord('a'))
        key.append(key_char)
    
    return ''.join(key)


def decrypt_vigenere(text: str, key: str) -> str:
    """
    Decrypt Vigenère cipher with a given key.
    
    Args:
        text: Ciphertext
        key: Decryption key
        
    Returns:
        Decrypted text
    """
    result = []
    key_pos = 0
    
    for char in text:
        if char.isalpha():
            # Get the shift for this position in the key
            key_char = key[key_pos % len(key)]
            key_pos += 1
            
            # Calculate shift value
            shift = ord(key_char.lower()) - ord('a')
            
            # Apply reverse shift
            ascii_offset = ord('a') if char.islower() else ord('A')
            decrypted = chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
            result.append(decrypted)
        else:
            result.append(char)
    
    return ''.join(result)


def decrypt_vigenere_preserve_format(text: str, key: str) -> str:
    """
    Decrypt Vigenère cipher preserving original format.
    
    Args:
        text: Ciphertext
        key: Decryption key
        
    Returns:
        Decrypted text
    """
    result = []
    key_pos = 0
    
    for char in text:
        if char.isalpha():
            # Get the shift for this position in the key
            key_char = key[key_pos % len(key)]
            key_pos += 1
            
            # Calculate shift value
            shift = ord(key_char.lower()) - ord('a')
            
            # Apply reverse shift
            ascii_offset = ord('a') if char.islower() else ord('A')
            decrypted = chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
            result.append(decrypted)
        else:
            result.append(char)
    
    return ''.join(result)


def decrypt_columnar(text: str, key_length: int) -> str:
    """
    Decrypt columnar transposition with a given key length.
    
    Args:
        text: Ciphertext
        key_length: Number of columns
        
    Returns:
        Decrypted text
    """
    # Calculate number of rows
    text_length = len(text)
    rows = text_length // key_length
    if text_length % key_length != 0:
        rows += 1
    
    # Create the grid
    grid = [[''] * key_length for _ in range(rows)]
    
    # Fill the grid
    for i, char in enumerate(text):
        col = i // rows
        row = i % rows
        if col < key_length:
            grid[row][col] = char
    
    # Read by rows
    result = []
    for row in grid:
        result.extend(row)
    
    return ''.join(result)


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


def find_repeating_key_xor(data: bytes, key_length: int) -> bytes:
    """
    Find a repeating-key XOR key of the given length.
    
    Args:
        data: Encrypted data
        key_length: Length of the key
        
    Returns:
        Key bytes or empty if detection fails
    """
    # Split data into blocks based on key position
    blocks = [b'' for _ in range(key_length)]
    for i, byte in enumerate(data):
        blocks[i % key_length] += bytes([byte])
    
    # Solve each block as a single-byte XOR
    key = bytearray()
    for block in blocks:
        best_score = 0
        best_key_byte = 0
        
        for key_byte in range(1, 256):
            decrypted = bytes(b ^ key_byte for b in block)
            
            # Check if the decrypted data might be text
            if is_printable_text(decrypted):
                try:
                    decoded_text = decrypted.decode('utf-8', errors='replace')
                    score = score_english_text(decoded_text)
                    
                    if score > best_score:
                        best_score = score
                        best_key_byte = key_byte
                except:
                    pass
        
        if best_score > 0.2:  # Use a lower threshold for individual blocks
            key.append(best_key_byte)
        else:
            return b''  # Failed to find a good key
    
    return bytes(key)


def decrypt_repeating_key_xor(data: bytes, key: bytes) -> bytes:
    """
    Decrypt data encrypted with repeating-key XOR.
    
    Args:
        data: Encrypted data
        key: Decryption key
        
    Returns:
        Decrypted data
    """
    decrypted = bytearray()
    
    for i, byte in enumerate(data):
        key_byte = key[i % len(key)]
        decrypted.append(byte ^ key_byte)
    
    return bytes(decrypted)


def apply_atbash(text: str) -> str:
    """
    Apply Atbash cipher (reverse alphabet).
    
    Args:
        text: Input text
        
    Returns:
        Transformed text
    """
    result = []
    
    for char in text:
        if char.islower():
            result.append(chr(219 - ord(char)))  # 219 = ord('a') + ord('z')
        elif char.isupper():
            result.append(chr(155 - ord(char)))  # 155 = ord('A') + ord('Z')
        else:
            result.append(char)
    
    return ''.join(result)


def decrypt_railfence(text: str, rails: int) -> str:
    """
    Decrypt Rail Fence (Zig-zag) cipher.
    
    Args:
        text: Ciphertext
        rails: Number of rails
        
    Returns:
        Decrypted text
    """
    if rails < 2 or len(text) <= rails:
        return text
    
    # Create the fence pattern
    fence = [[''] * len(text) for _ in range(rails)]
    
    # Fill the fence with markers
    rail = 0
    direction = 1
    for i in range(len(text)):
        fence[rail][i] = '*'
        rail += direction
        if rail == rails - 1 or rail == 0:
            direction *= -1
    
    # Fill the fence with the ciphertext
    index = 0
    for r in range(rails):
        for c in range(len(text)):
            if fence[r][c] == '*':
                fence[r][c] = text[index]
                index += 1
    
    # Read off the fence
    result = []
    rail = 0
    direction = 1
    for i in range(len(text)):
        result.append(fence[rail][i])
        rail += direction
        if rail == rails - 1 or rail == 0:
            direction *= -1
    
    return ''.join(result)
