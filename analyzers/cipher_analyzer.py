"""
Cipher analyzer for Crypto Hunter.
Detects and solves various classical ciphers.
"""

import re
import string
import collections
from itertools import cycle
from core.state import State
from analyzers.base import register_analyzer, analyzer_compatibility

# English letter frequency (most to least common)
ENGLISH_FREQ = "ETAOINSRHDLUCMFYWGPBVKXQJZ".lower()

# Common words for analyzing substitution ciphers
COMMON_ENGLISH_WORDS = {
    'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i',
    'it', 'for', 'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at',
    'this', 'but', 'his', 'by', 'from', 'they', 'we', 'say', 'her', 'she',
    'or', 'an', 'will', 'my', 'one', 'all', 'would', 'there', 'their', 'what',
    'so', 'up', 'out', 'if', 'about', 'who', 'get', 'which', 'go', 'me',
    'when', 'make', 'can', 'like', 'time', 'no', 'just', 'him', 'know', 'take'
}

@register_analyzer("cipher_analyzer")
@analyzer_compatibility(requires_text=True)
def analyze_ciphers(state: State, cipher_type: str = None, input_data: str = None) -> State:
    """
    Detect and solve various classical ciphers in the text.

    Args:
        state: Current puzzle state
        cipher_type: Optional specific cipher type to analyze
        input_data: Optional specific data to analyze instead of state.puzzle_text

    Returns:
        Updated state
    """
    # Use input_data if provided, otherwise use state.puzzle_text
    if input_data is not None:
        text = input_data
    elif state.puzzle_text:
        text = state.puzzle_text
    else:
        return state

    state.add_insight(
        "Starting classical cipher analysis",
        analyzer="cipher_analyzer"
    )

    # If a specific cipher type is requested, only analyze that one
    if cipher_type:
        state.add_insight(
            f"Analyzing specifically for {cipher_type} cipher",
            analyzer="cipher_analyzer"
        )

        if cipher_type.lower() == "caesar":
            analyze_caesar_cipher(state, text)
        elif cipher_type.lower() == "vigenere":
            analyze_vigenere_cipher(state, text)
        elif cipher_type.lower() == "substitution":
            analyze_substitution_cipher(state, text)
        elif cipher_type.lower() == "transposition":
            analyze_transposition_cipher(state, text)
        elif cipher_type.lower() == "baconian":
            analyze_baconian_cipher(state, text)
        elif cipher_type.lower() == "atbash":
            analyze_atbash_cipher(state, text)
        elif cipher_type.lower() == "rail_fence":
            analyze_rail_fence_cipher(state, text)
        elif cipher_type.lower() == "xor":
            analyze_xor_cipher(state, text)
        else:
            state.add_insight(
                f"Unknown cipher type '{cipher_type}'. Analyzing all cipher types instead.",
                analyzer="cipher_analyzer"
            )
            # If unknown cipher type, analyze all
            analyze_caesar_cipher(state, text)
            analyze_vigenere_cipher(state, text)
            analyze_substitution_cipher(state, text)
            analyze_transposition_cipher(state, text)
            analyze_baconian_cipher(state, text)
            analyze_atbash_cipher(state, text)
            analyze_rail_fence_cipher(state, text)
            analyze_xor_cipher(state, text)
    else:
        # Analyze for all cipher types
        analyze_caesar_cipher(state, text)
        analyze_vigenere_cipher(state, text)
        analyze_substitution_cipher(state, text)
        analyze_transposition_cipher(state, text)
        analyze_baconian_cipher(state, text)
        analyze_atbash_cipher(state, text)
        analyze_rail_fence_cipher(state, text)
        analyze_xor_cipher(state, text)

    # Check related files if any
    if state.related_files:
        state.add_insight(
            f"Checking {len(state.related_files)} related files for cipher patterns",
            analyzer="cipher_analyzer"
        )

        for filename, file_info in state.related_files.items():
            if file_info.get("text_content"):
                related_text = file_info["text_content"]
                state.add_insight(
                    f"Analyzing related file {filename} for cipher patterns",
                    analyzer="cipher_analyzer"
                )

                # Perform basic cipher checks on the related file
                if len(related_text) > 20:  # Only analyze if there's enough text
                    analyze_caesar_cipher(state, related_text, is_related=True, filename=filename)

    return state

def analyze_caesar_cipher(state: State, text: str, is_related=False, filename=None) -> None:
    """
    Analyze text for potential Caesar cipher.

    Args:
        state: Current puzzle state
        text: Text to analyze
        is_related: Whether this is a related file
        filename: Name of the related file (if applicable)
    """
    # Clean text to only include letters
    text = text.lower()
    clean_text = ''.join(c for c in text if c in string.ascii_lowercase)

    if len(clean_text) < 5:
        return  # Not enough text to analyze

    # Calculate letter frequencies
    letter_freq = collections.Counter(clean_text).most_common()
    letter_freq = [letter for letter, _ in letter_freq if letter in string.ascii_lowercase]

    # Calculate most likely shift by comparing with English frequencies
    # Assuming most common letter in English is 'e'
    if not letter_freq:
        return

    potential_shifts = []
    top_letters = letter_freq[:3]  # Consider top 3 most frequent letters

    for cipher_letter in top_letters:
        # Try common English letters e, t, a as the original
        for plain_letter in 'eta':
            shift = (ord(cipher_letter) - ord(plain_letter)) % 26
            potential_shifts.append(shift)

    # Try all shifts and score them
    shift_scores = {}
    best_shift = None
    best_score = -1
    best_decoded = None

    for shift in range(26):
        decoded = caesar_decode(clean_text, shift)
        score = score_english_text(decoded)
        shift_scores[shift] = score

        if score > best_score:
            best_score = score
            best_shift = shift
            best_decoded = decoded

    # Only report if the best score is good enough
    prefix = f"Related file {filename}: " if is_related else ""

    if best_score > 0.4:  # Higher confidence
        state.add_insight(
            f"{prefix}Text appears to be a Caesar cipher with shift {best_shift}",
            analyzer="cipher_analyzer"
        )

        # Add transformation with the decoded text
        source = f"Related file {filename}" if is_related else "Puzzle text"
        state.add_transformation(
            name=f"Caesar Cipher (Shift {best_shift})",
            description=f"Decoded Caesar cipher from {source} with shift {best_shift}",
            input_data=text[:100] + "..." if len(text) > 100 else text,
            output_data=caesar_decode(text, best_shift),
            analyzer="cipher_analyzer"
        )
    elif best_score > 0.2:  # Lower confidence
        # Add all potential candidates
        top_shifts = sorted(shift_scores.items(), key=lambda x: x[1], reverse=True)[:3]

        # Only add top shifts with reasonable scores
        candidates = [(shift, score) for shift, score in top_shifts if score > 0.1]

        if candidates:
            state.add_insight(
                f"{prefix}Text might be a Caesar cipher. Top candidate shifts: " + 
                ", ".join([f"{s} (score: {sc:.2f})" for s, sc in candidates]),
                analyzer="cipher_analyzer"
            )

            # Add transformation for the best candidate
            source = f"Related file {filename}" if is_related else "Puzzle text"
            state.add_transformation(
                name=f"Potential Caesar Cipher (Shift {best_shift})",
                description=f"Potentially decoded Caesar cipher from {source} with shift {best_shift}",
                input_data=text[:100] + "..." if len(text) > 100 else text,
                output_data=caesar_decode(text, best_shift),
                analyzer="cipher_analyzer"
            )
    else:
        # Add all shifts as a transformation for manual inspection
        all_shifts = ""
        for shift in range(26):
            all_shifts += f"Shift {shift}: {caesar_decode(text[:40], shift)}\n"

        source = f"Related file {filename}" if is_related else "Puzzle text"
        state.add_transformation(
            name="All Caesar Shifts",
            description=f"All 26 possible Caesar shifts of {source} for manual inspection",
            input_data=text[:100] + "..." if len(text) > 100 else text,
            output_data=all_shifts,
            analyzer="cipher_analyzer"
        )

def analyze_vigenere_cipher(state: State, text: str) -> None:
    """
    Analyze text for potential Vigenère cipher.

    Args:
        state: Current puzzle state
        text: Text to analyze
    """
    # Clean text to only include letters
    text = text.lower()
    clean_text = ''.join(c for c in text if c in string.ascii_lowercase)

    if len(clean_text) < 20:
        return  # Not enough text to analyze

    # Check for repeating sequences which can indicate key length
    repeats = find_repeating_sequences(clean_text)
    if not repeats:
        return

    # Determine likely key lengths from the repeats
    key_lengths = []
    for seq, positions in repeats.items():
        if len(positions) < 2:
            continue

        # Calculate differences between positions
        diffs = [positions[i+1] - positions[i] for i in range(len(positions)-1)]

        # Count potential key lengths based on greatest common divisor
        for diff in diffs:
            for length in range(2, 13):  # Check key lengths from 2 to 12
                if diff % length == 0:
                    key_lengths.append(length)

    # Count occurrences of each key length
    key_length_counts = collections.Counter(key_lengths)

    if not key_length_counts:
        return

    # Get the most likely key lengths
    likely_key_lengths = key_length_counts.most_common(3)

    # Try to crack each likely key length
    potential_keys = []

    for key_length, _ in likely_key_lengths:
        # Split text into columns
        columns = [''] * key_length
        for i, char in enumerate(clean_text):
            columns[i % key_length] += char

        # Find shift for each column (assume Caesar cipher)
        key = ''
        for column in columns:
            # Find the most likely shift for this column
            letter_freq = collections.Counter(column).most_common()
            if not letter_freq:
                continue

            # Assume the most common letter corresponds to 'e' in English
            most_common = letter_freq[0][0]
            shift = (ord(most_common) - ord('e')) % 26
            key += chr(shift + ord('a'))

        # Decode with this key and score the result
        decoded = vigenere_decode(clean_text, key)
        score = score_english_text(decoded)

        potential_keys.append((key, score, decoded))

    # Sort by score
    potential_keys.sort(key=lambda x: x[1], reverse=True)

    # Report findings
    if potential_keys and potential_keys[0][1] > 0.3:
        best_key, best_score, best_decoded = potential_keys[0]

        state.add_insight(
            f"Text appears to be a Vigenère cipher with key '{best_key}'",
            analyzer="cipher_analyzer"
        )

        # Add transformation with the decoded text
        state.add_transformation(
            name=f"Vigenère Cipher (Key: {best_key})",
            description=f"Decoded Vigenère cipher with key '{best_key}'",
            input_data=text[:100] + "..." if len(text) > 100 else text,
            output_data=vigenere_decode(text, best_key),
            analyzer="cipher_analyzer"
        )
    elif potential_keys and potential_keys[0][1] > 0.1:
        best_key, best_score, best_decoded = potential_keys[0]

        state.add_insight(
            f"Text might be a Vigenère cipher. Potential key: '{best_key}' (score: {best_score:.2f})",
            analyzer="cipher_analyzer"
        )

        # Add transformation for the best candidate
        state.add_transformation(
            name=f"Potential Vigenère Cipher (Key: {best_key})",
            description=f"Potentially decoded Vigenère cipher with key '{best_key}'",
            input_data=text[:100] + "..." if len(text) > 100 else text,
            output_data=vigenere_decode(text, best_key),
            analyzer="cipher_analyzer"
        )

def analyze_substitution_cipher(state: State, text: str) -> None:
    """
    Analyze text for potential substitution cipher.

    Args:
        state: Current puzzle state
        text: Text to analyze
    """
    # Clean text to only include letters
    text = text.lower()
    clean_text = ''.join(c for c in text if c in string.ascii_lowercase)

    if len(clean_text) < 30:
        return  # Not enough text to analyze

    # Calculate letter frequencies
    letter_freq = collections.Counter(clean_text).most_common()
    unique_letters = len([letter for letter, _ in letter_freq if letter in string.ascii_lowercase])

    # Check if it's a potential substitution cipher
    if 10 <= unique_letters <= 26:
        # Calculate frequency of each letter as a percentage
        total_letters = sum(count for _, count in letter_freq)
        freq_percentages = {letter: (count / total_letters) * 100 
                            for letter, count in letter_freq}

        # Compare with English letter frequencies
        english_freqs = {
            'e': 12.02, 't': 9.10, 'a': 8.12, 'o': 7.68, 'i': 7.31,
            'n': 6.95, 's': 6.28, 'r': 6.02, 'h': 5.92, 'd': 4.32,
            'l': 3.98, 'u': 2.88, 'c': 2.71, 'm': 2.61, 'f': 2.30,
            'y': 2.11, 'w': 2.09, 'g': 2.03, 'p': 1.82, 'b': 1.49,
            'v': 1.11, 'k': 0.69, 'x': 0.17, 'q': 0.11, 'j': 0.10, 'z': 0.07
        }

        # Create letter mapping based on frequency order
        cipher_letters = [letter for letter, _ in letter_freq]
        plain_letters = list(ENGLISH_FREQ)

        # Create a tentative mapping
        mapping = {}
        for i in range(min(len(cipher_letters), len(plain_letters))):
            mapping[cipher_letters[i]] = plain_letters[i]

        # Apply mapping to decode
        decoded = simple_substitution_decode(clean_text, mapping)
        score = score_english_text(decoded)

        # Only report if likely
        if score > 0.1:
            state.add_insight(
                "Text appears to be a simple substitution cipher",
                analyzer="cipher_analyzer"
            )

            # Create a mapping table for the transformation
            mapping_table = "Cipher Letter -> Plain Letter\n"
            for cipher_letter, plain_letter in mapping.items():
                mapping_table += f"{cipher_letter} -> {plain_letter}\n"

            # Add transformation with the tentative decoding
            state.add_transformation(
                name="Substitution Cipher (Frequency Analysis)",
                description="Tentative decoding based on letter frequency analysis",
                input_data=text[:100] + "..." if len(text) > 100 else text,
                output_data=f"Mapping:\n{mapping_table}\n\nDecoded text:\n{simple_substitution_decode(text, mapping)}",
                analyzer="cipher_analyzer"
            )

def analyze_transposition_cipher(state: State, text: str) -> None:
    """
    Analyze text for potential transposition ciphers.

    Args:
        state: Current puzzle state
        text: Text to analyze
    """
    # Clean text to only include letters
    text = text.lower()
    clean_text = ''.join(c for c in text if c in string.ascii_lowercase)

    if len(clean_text) < 20:
        return  # Not enough text to analyze

    # Check if length is a perfect square (for columnar or grid transposition)
    from math import isqrt

    length = len(clean_text)
    sqrt_len = isqrt(length)

    # Check for columnar transposition
    state.add_insight(
        "Checking for columnar transposition cipher patterns",
        analyzer="cipher_analyzer"
    )

    # Try different column counts
    potential_cols = []
    for cols in range(2, 11):  # Try 2 to 10 columns
        if length % cols == 0:
            potential_cols.append(cols)

    if potential_cols:
        # Add transformation for columnar transposition attempts
        output = "Potential Columnar Transpositions:\n\n"

        for cols in potential_cols:
            rows = length // cols

            # Read by columns
            columnar_decoded1 = ""
            for r in range(rows):
                for c in range(cols):
                    index = c * rows + r
                    if index < length:
                        columnar_decoded1 += clean_text[index]

            # Read by columns, but column order may be different (try a simple ordering)
            columnar_decoded2 = ""
            col_order = list(range(cols))
            col_order.reverse()  # Try reverse order

            for r in range(rows):
                for c in col_order:
                    index = c * rows + r
                    if index < length:
                        columnar_decoded2 += clean_text[index]

            # Score both attempts
            score1 = score_english_text(columnar_decoded1)
            score2 = score_english_text(columnar_decoded2)

            output += f"{cols} columns (read down, left-to-right) - Score: {score1:.2f}\n"
            output += f"{columnar_decoded1[:50]}...\n\n"

            output += f"{cols} columns (read down, right-to-left) - Score: {score2:.2f}\n"
            output += f"{columnar_decoded2[:50]}...\n\n"

            # Check if either appears to be correct
            if score1 > 0.2 or score2 > 0.2:
                state.add_insight(
                    f"Text might be a columnar transposition cipher with {cols} columns",
                    analyzer="cipher_analyzer"
                )

        state.add_transformation(
            name="Columnar Transposition Attempts",
            description="Potential columnar transposition decodings",
            input_data=text[:100] + "..." if len(text) > 100 else text,
            output_data=output,
            analyzer="cipher_analyzer"
        )

    # Check for rail fence cipher
    output = "Rail Fence Cipher Attempts:\n\n"
    potential_rails = False

    for rails in range(2, 6):  # Try 2 to 5 rails
        decoded = rail_fence_decode(clean_text, rails)
        score = score_english_text(decoded)

        output += f"{rails} rails - Score: {score:.2f}\n"
        output += f"{decoded[:50]}...\n\n"

        if score > 0.2:
            state.add_insight(
                f"Text might be a rail fence cipher with {rails} rails",
                analyzer="cipher_analyzer"
            )
            potential_rails = True

    if potential_rails:
        state.add_transformation(
            name="Rail Fence Cipher Attempts",
            description="Potential rail fence cipher decodings",
            input_data=text[:100] + "..." if len(text) > 100 else text,
            output_data=output,
            analyzer="cipher_analyzer"
        )

def analyze_baconian_cipher(state: State, text: str) -> None:
    """
    Analyze text for potential Baconian cipher.

    Args:
        state: Current puzzle state
        text: Text to analyze
    """
    # Baconian cipher uses two distinct symbols (traditionally A and B)
    # Check if text can be interpreted as binary

    # Clean text and look for binary-like patterns
    clean_text = ''.join(c for c in text.lower() if c in 'ab01 \t\n').strip()

    if len(clean_text) < 20:
        return  # Not enough text to analyze

    # Check if the text consists of primarily two symbols
    char_counts = collections.Counter(clean_text)
    main_chars = [c for c, count in char_counts.most_common() if c not in ' \t\n']

    if len(main_chars) == 2:
        # Try to interpret as Baconian cipher
        # Baconian cipher: A = "00000", B = "00001", ..., Z = "11001"

        # Map the two main characters to 0 and 1
        char_map = {main_chars[0]: '0', main_chars[1]: '1'}

        # Convert text to binary
        binary = ''.join(char_map.get(c, '') for c in clean_text)

        # Split into 5-bit groups
        groups = [binary[i:i+5] for i in range(0, len(binary), 5) if i+5 <= len(binary)]

        # Convert to letters
        baconian_map = {
            '00000': 'a', '00001': 'b', '00010': 'c', '00011': 'd', '00100': 'e',
            '00101': 'f', '00110': 'g', '00111': 'h', '01000': 'i', '01001': 'j',
            '01010': 'k', '01011': 'l', '01100': 'm', '01101': 'n', '01110': 'o',
            '01111': 'p', '10000': 'q', '10001': 'r', '10010': 's', '10011': 't',
            '10100': 'u', '10101': 'v', '10110': 'w', '10111': 'x', '11000': 'y',
            '11001': 'z'
        }

        decoded = ''
        for group in groups:
            decoded += baconian_map.get(group, '?')

        # Check if this could be valid text
        score = score_english_text(decoded)

        if score > 0.2:
            state.add_insight(
                f"Text might be a Baconian cipher using {main_chars[0]} and {main_chars[1]}",
                analyzer="cipher_analyzer"
            )

            state.add_transformation(
                name="Baconian Cipher",
                description=f"Decoded Baconian cipher (mapping {main_chars[0]}=0, {main_chars[1]}=1)",
                input_data=text[:100] + "..." if len(text) > 100 else text,
                output_data=decoded,
                analyzer="cipher_analyzer"
            )

        # Try the reverse mapping as well
        char_map = {main_chars[0]: '1', main_chars[1]: '0'}

        # Convert text to binary
        binary = ''.join(char_map.get(c, '') for c in clean_text)

        # Split into 5-bit groups
        groups = [binary[i:i+5] for i in range(0, len(binary), 5) if i+5 <= len(binary)]

        # Convert to letters
        decoded = ''
        for group in groups:
            decoded += baconian_map.get(group, '?')

        # Check if this could be valid text
        score = score_english_text(decoded)

        if score > 0.2:
            state.add_insight(
                f"Text might be a Baconian cipher using {main_chars[0]} and {main_chars[1]} (reverse mapping)",
                analyzer="cipher_analyzer"
            )

            state.add_transformation(
                name="Baconian Cipher (Reverse Mapping)",
                description=f"Decoded Baconian cipher (mapping {main_chars[0]}=1, {main_chars[1]}=0)",
                input_data=text[:100] + "..." if len(text) > 100 else text,
                output_data=decoded,
                analyzer="cipher_analyzer"
            )

def analyze_atbash_cipher(state: State, text: str) -> None:
    """
    Analyze text for potential Atbash cipher.

    Args:
        state: Current puzzle state
        text: Text to analyze
    """
    # Atbash cipher flips the alphabet (A->Z, B->Y, etc.)
    # It's easy to check by just applying it and seeing if the result is readable

    # Clean text to only include letters
    text = text.lower()
    clean_text = ''.join(c for c in text if c in string.ascii_lowercase)

    if len(clean_text) < 10:
        return  # Not enough text to analyze

    # Apply Atbash cipher
    decoded = atbash_decode(clean_text)
    score = score_english_text(decoded)

    if score > 0.2:
        state.add_insight(
            "Text appears to be encoded with an Atbash cipher",
            analyzer="cipher_analyzer"
        )

        state.add_transformation(
            name="Atbash Cipher",
            description="Decoded Atbash cipher (A->Z, B->Y, etc.)",
            input_data=text[:100] + "..." if len(text) > 100 else text,
            output_data=atbash_decode(text),
            analyzer="cipher_analyzer"
        )

def analyze_rail_fence_cipher(state: State, text: str) -> None:
    """
    Analyze text for potential Rail Fence cipher.
    This is handled by the transposition cipher analysis.

    Args:
        state: Current puzzle state
        text: Text to analyze
    """
    # This is now handled by analyze_transposition_cipher
    pass

def analyze_xor_cipher(state: State, text: str) -> None:
    """
    Analyze text for potential XOR cipher.

    Args:
        state: Current puzzle state
        text: Text to analyze
    """
    # XOR is typically used on binary data, but we can try on text too

    # Only analyze if the text looks like it might be hex or binary encoded
    is_hex = all(c in string.hexdigits for c in text.strip())
    is_binary = all(c in '01 \t\n' for c in text.strip())

    if not (is_hex or is_binary):
        return

    state.add_insight(
        "Text contains only hex or binary characters, checking for XOR cipher",
        analyzer="cipher_analyzer"
    )

    # If hex, convert to bytes
    if is_hex:
        try:
            # Clean hex string
            clean_hex = ''.join(c for c in text if c in string.hexdigits)

            # Pad if necessary
            if len(clean_hex) % 2 == 1:
                clean_hex = '0' + clean_hex

            # Convert to bytes
            data = bytes.fromhex(clean_hex)

            # Try simple XOR keys
            output = "XOR Cipher Attempts (Hex Input):\n\n"

            for key in range(1, 256):
                xored = bytes([b ^ key for b in data])

                # See if the result is printable ASCII
                printable_ratio = sum(32 <= b <= 126 for b in xored) / len(xored)

                if printable_ratio > 0.8:
                    # Try to decode as text
                    try:
                        decoded = xored.decode('ascii', errors='replace')
                        score = score_english_text(decoded)

                        output += f"Key: {key} (0x{key:02X}) - Score: {score:.2f}\n"
                        output += f"{decoded[:50]}...\n\n"

                        if score > 0.2:
                            state.add_insight(
                                f"Text might be XOR encrypted with key {key} (0x{key:02X})",
                                analyzer="cipher_analyzer"
                            )
                    except:
                        pass

            state.add_transformation(
                name="XOR Cipher Attempts (Hex Input)",
                description="Potential XOR cipher decodings from hex input",
                input_data=text[:100] + "..." if len(text) > 100 else text,
                output_data=output,
                analyzer="cipher_analyzer"
            )
        except:
            state.add_insight(
                "Error processing hex data for XOR analysis",
                analyzer="cipher_analyzer"
            )

    # If binary, convert to bytes and analyze
    if is_binary:
        try:
            # Clean binary string
            clean_binary = ''.join(c for c in text if c in '01')

            # Pad to whole bytes
            remainder = len(clean_binary) % 8
            if remainder != 0:
                clean_binary = '0' * (8 - remainder) + clean_binary

            # Convert to bytes
            data = bytes(int(clean_binary[i:i+8], 2) for i in range(0, len(clean_binary), 8))

            # Try simple XOR keys
            output = "XOR Cipher Attempts (Binary Input):\n\n"

            for key in range(1, 256):
                xored = bytes([b ^ key for b in data])

                # See if the result is printable ASCII
                printable_ratio = sum(32 <= b <= 126 for b in xored) / len(xored)

                if printable_ratio > 0.8:
                    # Try to decode as text
                    try:
                        decoded = xored.decode('ascii', errors='replace')
                        score = score_english_text(decoded)

                        output += f"Key: {key} (0x{key:02X}) - Score: {score:.2f}\n"
                        output += f"{decoded[:50]}...\n\n"

                        if score > 0.2:
                            state.add_insight(
                                f"Text might be XOR encrypted with key {key} (0x{key:02X})",
                                analyzer="cipher_analyzer"
                            )
                    except:
                        pass

            state.add_transformation(
                name="XOR Cipher Attempts (Binary Input)",
                description="Potential XOR cipher decodings from binary input",
                input_data=text[:100] + "..." if len(text) > 100 else text,
                output_data=output,
                analyzer="cipher_analyzer"
            )
        except:
            state.add_insight(
                "Error processing binary data for XOR analysis",
                analyzer="cipher_analyzer"
            )

# Utility functions

def caesar_decode(text: str, shift: int) -> str:
    """
    Decode Caesar cipher with the given shift.

    Args:
        text: Encoded text
        shift: Shift value (0-25)

    Returns:
        Decoded text
    """
    result = ""

    for char in text:
        if char.isalpha():
            ascii_offset = ord('a') if char.islower() else ord('A')
            # Shift the character and wrap around the alphabet
            result += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
        else:
            result += char

    return result

def vigenere_decode(text: str, key: str) -> str:
    """
    Decode Vigenère cipher with the given key.

    Args:
        text: Encoded text
        key: Encryption key

    Returns:
        Decoded text
    """
    result = ""
    key_iter = cycle(key.lower())

    for char in text:
        if char.isalpha():
            ascii_offset = ord('a') if char.islower() else ord('A')
            key_char = next(key_iter)
            key_shift = ord(key_char) - ord('a')
            # Apply the Vigenère decoding formula
            result += chr((ord(char) - ascii_offset - key_shift) % 26 + ascii_offset)
        else:
            result += char
            # Skip key iteration for non-alphabetic characters
            next(key_iter)

    return result

def simple_substitution_decode(text: str, mapping: dict) -> str:
    """
    Decode simple substitution cipher with the given mapping.

    Args:
        text: Encoded text
        mapping: Dictionary mapping cipher letters to plain letters

    Returns:
        Decoded text
    """
    result = ""

    for char in text:
        if char.lower() in mapping:
            if char.isupper():
                result += mapping[char.lower()].upper()
            else:
                result += mapping[char]
        else:
            result += char

    return result

def rail_fence_decode(text: str, rails: int) -> str:
    """
    Decode Rail Fence cipher with the given number of rails.

    Args:
        text: Encoded text
        rails: Number of rails

    Returns:
        Decoded text
    """
    if rails < 2:
        return text

    # Create a 2D array for the rail fence
    fence = [[''] * len(text) for _ in range(rails)]

    # Fill the fence
    r, c = 0, 0
    direction = 1  # 1 for down, -1 for up

    # Mark positions in the fence
    for i in range(len(text)):
        fence[r][c] = '*'
        c += 1
        r += direction

        # Change direction if needed
        if r == rails - 1 or r == 0:
            direction *= -1

    # Fill with the characters from the text
    index = 0
    for r in range(rails):
        for c in range(len(text)):
            if fence[r][c] == '*' and index < len(text):
                fence[r][c] = text[index]
                index += 1

    # Read in zig-zag pattern
    result = ''
    r, c = 0, 0
    direction = 1

    for i in range(len(text)):
        result += fence[r][c]
        c += 1
        r += direction

        if r == rails - 1 or r == 0:
            direction *= -1

    return result

def atbash_decode(text: str) -> str:
    """
    Decode Atbash cipher.

    Args:
        text: Encoded text

    Returns:
        Decoded text
    """
    result = ""

    for char in text:
        if char.isalpha():
            ascii_offset = ord('a') if char.islower() else ord('A')
            # Flip the character in the alphabet
            result += chr(ascii_offset + (25 - (ord(char) - ascii_offset)))
        else:
            result += char

    return result

def find_repeating_sequences(text: str, min_length=3, max_length=5) -> dict:
    """
    Find repeating sequences in the text.

    Args:
        text: Text to analyze
        min_length: Minimum sequence length to consider
        max_length: Maximum sequence length to consider

    Returns:
        Dictionary mapping sequences to their positions
    """
    result = {}

    for length in range(min_length, max_length + 1):
        for i in range(len(text) - length + 1):
            seq = text[i:i+length]

            # Find all occurrences
            positions = []
            start = 0
            while True:
                pos = text.find(seq, start)
                if pos == -1:
                    break
                positions.append(pos)
                start = pos + 1

            # Only add if there are multiple occurrences
            if len(positions) > 1:
                result[seq] = positions

    return result

def score_english_text(text: str) -> float:
    """
    Score text based on how likely it is to be valid English.

    Args:
        text: Text to score

    Returns:
        Score from 0.0 to 1.0 (higher is more likely to be English)
    """
    # Clean text to only include letters and spaces
    text = text.lower()

    # Check character frequency
    char_counts = collections.Counter(text)

    # Calculate letter frequency score
    freq_score = 0
    english_freqs = {
        'e': 12.02, 't': 9.10, 'a': 8.12, 'o': 7.68, 'i': 7.31,
        'n': 6.95, 's': 6.28, 'r': 6.02, 'h': 5.92, 'd': 4.32,
        'l': 3.98, 'u': 2.88, 'c': 2.71, 'm': 2.61, 'f': 2.30,
        'y': 2.11, 'w': 2.09, 'g': 2.03, 'p': 1.82, 'b': 1.49,
        'v': 1.11, 'k': 0.69, 'x': 0.17, 'q': 0.11, 'j': 0.10, 'z': 0.07
    }

    total_chars = sum(count for char, count in char_counts.items() if char.isalpha())
    if total_chars == 0:
        return 0

    for char, freq in english_freqs.items():
        actual_freq = char_counts.get(char, 0) / total_chars * 100 if total_chars > 0 else 0
        freq_score += min(actual_freq, freq) / max(actual_freq, freq) if actual_freq > 0 and freq > 0 else 0

    freq_score /= len(english_freqs)

    # Check for common English words
    words = text.split()
    word_score = 0

    for word in words:
        if word in COMMON_ENGLISH_WORDS:
            word_score += 1

    word_score = word_score / len(words) if words else 0

    # Check for vowel/consonant ratio
    vowels = sum(char_counts.get(c, 0) for c in 'aeiou')
    vowel_ratio = vowels / total_chars if total_chars > 0 else 0
    vowel_score = 1 - abs(vowel_ratio - 0.4) / 0.4  # 40% vowels is ideal

    # Combined score
    combined_score = 0.5 * freq_score + 0.3 * word_score + 0.2 * vowel_score

    return combined_score


analyze = analyze_ciphers